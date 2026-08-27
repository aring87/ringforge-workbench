"""Assemble one case's modules and produce a single verdict.

Phase 4a of `docs/SCORING.md`. This is the part that knows about disk: where a
case keeps its static summary, where a detonation writes its run summary, which
of two historical layouts a folder is in. `verdict.combine` is the part that
decides, and it is deliberately separate so that the deciding can be tested
without building a case folder.

**This replaced `scoring.combined_score_from_case_dir`, which is gone.** It was
kept alive for exactly one phase: 4a wrote `combined_verdict.json` beside the
additive `combined_score.json` and changed no consumers, and 4b moved the
consumers and deleted the old path. A shape change and a consumer migration in
one commit would have left no working state to bisect back to.

A case folder from before the change still has a `combined_score.json` on disk.
It is deliberately not read: its `total_score` was a 0-100 sum banded at 8/20/30,
and rendering it beside a corroboration verdict would put two incompatible
numbers on one page.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verdict.combine import categories_from_json, combine

from static_triage_engine.categories import spec_categories, static_categories
from static_triage_engine.scoring import (
    _extract_techniques,
    _is_weak_vt_noise,
    _safe_count,
    _safe_load_json,
)

#: Written next to the additive `combined_score.json`, not over it. Both exist
#: for one release; the additive one goes when its last reader does.
VERDICT_FILENAME = "combined_verdict.json"

#: Engines agreeing before a third-party opinion is allowed to floor a clean
#: local verdict.
#:
#: **Five, and not one.** One or two detections is the noise floor of
#: multi-engine scanning -- `_is_weak_vt_noise` already encodes that -- and a
#: dissent floor that fires on it would move a large fraction of ordinary
#: software to Needs Review while teaching everyone to ignore the band. Five
#: independent engines is a disagreement worth recording.
DISSENT_MALICIOUS_THRESHOLD = 5

#: Directory names that are a module inside a case rather than the case itself.
_MODULE_DIRS = {"dynamic_analysis", "static_analysis", "spec_analysis",
                "api_analysis", "extension_analysis"}


def case_home(case_dir: str | Path) -> Path:
    """Normalise a path that may point at a module directory inside a case."""
    path = Path(case_dir)
    return path.parent if path.name in _MODULE_DIRS else path


def _newest(paths: list[Path]) -> dict[str, Any] | None:
    """The most recently written of several candidate layouts, or None.

    **`None` rather than `{}` matters here.** An empty dict means the collector
    ran and produced nothing; absence means it never ran, and the category
    contract turns the second into `collected: false`. Collapsing them is the
    mistake the whole model exists to prevent, and this function is where a
    case folder would have collapsed them.
    """
    existing = [p for p in paths if p.exists()]
    if not existing:
        return None
    newest = sorted(existing, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    loaded = _safe_load_json(newest)
    return loaded if isinstance(loaded, dict) else None


def virustotal_dissent(summary: dict[str, Any] | None) -> tuple[bool, str]:
    """Does VirusTotal disagree strongly enough to floor a clean verdict?

    VirusTotal is not a category and never becomes one: it is other people's
    conclusion about the same file, and counting it as corroboration would let a
    sample reach a high band on one local observation plus somebody else's
    opinion. What it can do is stop us reporting *clean* when a meaningful
    number of engines say otherwise -- capped at Needs Review, which is the band
    for one unexplained observation.

    The thresholds live here rather than in `verdict/` on purpose. The moment
    the module that decides bands also knows what VirusTotal is, its numbers
    start being tuned to move verdicts.
    """
    vt = (summary or {}).get("virustotal")
    if not isinstance(vt, dict) or not vt.get("found"):
        return False, ""

    malicious = _safe_count(vt.get("malicious", 0))
    suspicious = _safe_count(vt.get("suspicious", 0))
    if _is_weak_vt_noise(vt):
        return False, ""
    if malicious < DISSENT_MALICIOUS_THRESHOLD:
        return False, ""

    return True, (
        f"VirusTotal reports {malicious} malicious and {suspicious} suspicious "
        f"detections that our own collectors did not reproduce. This is "
        f"third-party dissent, not local evidence -- treat it as a reason to "
        f"check coverage rather than as a finding."
    )


def load_case(case_dir: str | Path) -> dict[str, Any]:
    """Read every module's output off disk, preserving what never ran.

    Returns a mapping of module name to its inputs, with modules that produced
    nothing left **out** rather than present and empty.
    """
    home = case_home(case_dir)
    static_dir = home / "static_analysis"
    dynamic_dir = home / "dynamic_analysis"
    spec_dir = home / "spec_analysis"

    def newest(*relative: str) -> dict[str, Any] | None:
        candidates: list[Path] = []
        for name in relative:
            candidates += [static_dir / name, static_dir / "metadata" / name,
                           home / name, home / "metadata" / name]
        return _newest(candidates)

    dynamic_candidates: list[Path] = []
    for root in (dynamic_dir / "dynamic_runs", home / "dynamic_runs"):
        if root.exists():
            dynamic_candidates += list(root.glob("*/metadata/dynamic_run_summary.json"))
            dynamic_candidates += list(root.glob("*/dynamic_run_summary.json"))
    dynamic_candidates += [
        dynamic_dir / "metadata" / "dynamic_run_summary.json",
        dynamic_dir / "dynamic_run_summary.json",
        home / "metadata" / "dynamic_run_summary.json",
        home / "dynamic_run_summary.json",
    ]

    return {
        "summary": newest("summary.json", "run_summary.json"),
        "iocs": newest("iocs.json"),
        "pe_meta": newest("pe_metadata.json"),
        "api_analysis": newest("api_analysis.json"),
        "yara_results": newest("yara_results.json"),
        "signing": newest("signing.json"),
        "dynamic": _newest(dynamic_candidates),
        "spec": _newest([
            spec_dir / "api_spec_analysis.json",
            spec_dir / "metadata" / "api_spec_analysis.json",
            home / "spec" / "api_spec_analysis.json",
            home / "api_spec_analysis.json",
            home / "metadata" / "api_spec_analysis.json",
        ]),
    }



def capa_succeeded(home: Path) -> bool | None:
    """Did capa actually run for this case? `None` when the run log is absent.

    Read from `runlog.json`, which is the only place that distinguishes "capa
    matched nothing" from "capa was not installed". Both leave the same empty
    `capa.json`-shaped hole everywhere else.
    """
    for candidate in (home / "runlog.json",
                      home / "static_analysis" / "runlog.json"):
        if not candidate.exists():
            continue
        try:
            entry = json.loads(candidate.read_text(
                encoding="utf-8", errors="replace")).get("capa")
        except (ValueError, OSError):
            return None
        if not isinstance(entry, dict):
            return None
        if entry.get("skipped"):
            return None
        return int(entry.get("returncode", 0) or 0) == 0
    return None


def static_categories_for_case(
    home: Path,
    summary: dict[str, Any] | None,
    iocs: dict[str, Any] | None,
    pe_meta: dict[str, Any] | None,
    api_analysis: dict[str, Any] | None,
    yara_results: dict[str, Any] | None,
    signing: dict[str, Any] | None,
) -> tuple[list[Any], int]:
    """The static categories for one case, from files on disk.

    **One place that knows how to feed `static_categories`.** This assembly --
    the technique extraction, and counting `"matches"` in whichever of two
    locations holds `capa.json` -- existed twice, in `combine_case` and in
    `static_verdict_for_case`, and the corpus measurement wanted it a third
    time. Three copies of a lookup is how the copies start disagreeing about
    which collector ran.
    """
    capa_path = next((p for p in (home / "static_analysis" / "capa.json",
                                  home / "capa.json") if p.exists()), None)
    return static_categories(
        capa_ok=capa_succeeded(home),
        summary=summary, iocs=iocs, pe_meta=pe_meta,
        api_analysis=api_analysis, yara_results=yara_results, signing=signing,
        techniques=_extract_techniques(summary) if summary is not None else None,
        capa_match_count=(
            capa_path.read_text(encoding="utf-8", errors="replace").count('"matches"')
            if capa_path else None),
    )


def combine_case(
    case_dir: str | Path,
    write_output: bool = True,
) -> dict[str, Any]:
    """One verdict for a case, from whichever modules actually ran."""
    home = case_home(case_dir)
    loaded = load_case(home)

    contributions: dict[str, Any] = {}

    # --- Static -------------------------------------------------------------
    #
    # The module counts as having run if *any* of its outputs exist. Each
    # individual collector then reports its own coverage, which is the level the
    # distinction actually matters at: a case with a summary but no YARA results
    # ran static analysis and did not run the YARA scan.
    static_inputs = {k: loaded[k] for k in
                     ("summary", "iocs", "pe_meta", "api_analysis",
                      "yara_results", "signing")}
    if any(v is not None for v in static_inputs.values()):
        contributions["static"] = static_categories_for_case(home, **static_inputs)

    # --- Dynamic ------------------------------------------------------------
    #
    # Rebuilt from the run summary rather than recomputed. The run happened in
    # another process, on another machine, and re-deriving its categories here
    # would mean maintaining a second implementation of the dynamic scorer that
    # nothing tests against a real run.
    dynamic_summary = loaded["dynamic"]
    if dynamic_summary is not None:
        # The run summary carries the whole scorer output under `score_detail`.
        # Falling back to the top level covers summaries written before that
        # nesting existed.
        detail = dynamic_summary.get("score_detail")
        block = detail if isinstance(detail, dict) else dynamic_summary
        cats = categories_from_json(block.get("categories"))
        if cats:
            contributions["dynamic"] = (cats, int(block.get("context_score", 0) or 0))

    # --- Spec ---------------------------------------------------------------
    if loaded["spec"] is not None:
        contributions["spec"] = spec_categories(loaded["spec"])

    dissent, dissent_detail = virustotal_dissent(loaded["summary"])
    result = combine(contributions, third_party_dissent=dissent,
                     dissent_detail=dissent_detail)
    result["case_dir"] = str(home)

    if write_output:
        payload = json.dumps(result, indent=2)
        (home / VERDICT_FILENAME).write_text(payload, encoding="utf-8",
                                             errors="replace")
        metadata = home / "metadata"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / VERDICT_FILENAME).write_text(payload, encoding="utf-8",
                                                 errors="replace")

    return result


# ---------------------------------------------------------------------------
# The static module's own verdict
# ---------------------------------------------------------------------------

def _confidence(result: dict[str, Any]) -> str:
    """How much the static verdict is worth on its own.

    Coverage first: a verdict from a run where a collector was dark is a low
    confidence verdict whatever it says, because the thing that would have
    disagreed was never asked. After that, corroboration -- one category is one
    observation, and one observation is not a case.

    **A clean static result never reaches high confidence.** Static analysis can
    establish that nothing was found; only watching the sample run can establish
    that nothing happens, and the module that does that is not this one.
    """
    if not result.get("coverage_complete", True):
        return "Low confidence"

    counts = result.get("counts", {})
    if counts.get("categories_strong", 0) >= 1 or counts.get("categories_present", 0) >= 3:
        return "High confidence"
    if counts.get("categories_present", 0) >= 1:
        return "Moderate confidence"
    return "Moderate confidence"


def static_verdict_for_case(
    case_dir: str | Path,
    summary: dict[str, Any] | None,
    iocs: dict[str, Any] | None,
    pe_meta: dict[str, Any] | None,
    api_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The static module's standalone verdict, for `summary.json`.

    Replaces `scoring.score_risk` plus `scoring.classify_verdict`, which between
    them produced a 0-40 additive score and a MALICIOUS / SUSPICIOUS / LOW_RISK
    / BENIGN band whose thresholds were 8 / 20 / 30 -- and which let a clean
    VirusTotal result suppress local observations.

    The case directory is still read for the collectors `engine.py` does not
    hold in memory, exactly as `score_risk` did. What changed is that a missing
    file now means `collected: false` rather than a quiet zero.

    Returns the combiner's shape plus `confidence`, `suspicious` and `benign` --
    the last two kept under their old names because `summary.json` carries them
    and the report renders them.
    """
    home = case_home(case_dir)

    def newest(*names: str) -> dict[str, Any] | None:
        candidates: list[Path] = []
        for name in names:
            candidates += [home / "static_analysis" / name,
                           home / "static_analysis" / "metadata" / name,
                           home / name, home / "metadata" / name]
        return _newest(candidates)

    if not isinstance(api_analysis, dict) or not api_analysis:
        api_analysis = newest("api_analysis.json")

    cats, context = static_categories_for_case(
        home, summary=summary, iocs=iocs, pe_meta=pe_meta,
        api_analysis=api_analysis, yara_results=newest("yara_results.json"),
        signing=newest("signing.json"))

    dissent, dissent_detail = virustotal_dissent(summary)
    result = combine({"static": (cats, context)},
                     third_party_dissent=dissent, dissent_detail=dissent_detail)

    result["confidence"] = _confidence(result)
    # Kept under their old names: `summary.json` carries them and the report
    # renders them as bullet lists. The content is better than it was -- these
    # are the category reasons, written to be read aloud, rather than scoring
    # messages with point values attached.
    result["suspicious"] = [e["reason"] for e in result["evidence"] if e["reason"]]

    benign: list[str] = []
    if not result["counts"]["categories_present"]:
        benign.append("No static evidence category fired.")
    if result["coverage_complete"]:
        benign.append("Every static collector ran.")
    else:
        # Not a benign observation, and it must not read as one -- but it is
        # what a reader scanning this list needs to see first.
        benign.append(
            "Coverage incomplete: "
            + ", ".join(result["uncollected_categories"])
            + " could not be checked.")
    # **This assignment was missing from 6684981 until 26 Aug.** The list was
    # built and dropped, so the key never existed -- and `engine.run_case`
    # reads `static["suspicious"], static["benign"]` on the line that writes
    # the summary. Every full engine run since the scoring rewrite has died
    # there with `KeyError: 'benign'`, on every sample.
    #
    # Nothing caught it because nothing ran `run_case`. The tests reach
    # `static_verdict_for_case` and `combine_case` directly, which is where the
    # interesting logic is and is exactly why the seam above them was the part
    # left uncovered. `test_engine_run_case.py` now runs the real thing.
    result["benign"] = benign
    return result
