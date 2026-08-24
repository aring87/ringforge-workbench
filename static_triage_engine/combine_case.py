"""Assemble one case's modules and produce a single verdict.

Phase 4a of `docs/SCORING.md`. This is the part that knows about disk: where a
case keeps its static summary, where a detonation writes its run summary, which
of two historical layouts a folder is in. `verdict.combine` is the part that
decides, and it is deliberately separate so that the deciding can be tested
without building a case folder.

**Written alongside `scoring.combined_score_from_case_dir`, not replacing it.**
The old writer keeps producing `combined_score.json` in the additive shape so
the GUI and the reports keep working; this one writes `combined_verdict.json`
next to it. Phase 4b moves the consumers and deletes the additive path, which is
the only safe order -- a shape change and a consumer migration in one commit
would leave no working state to bisect back to.
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
        techniques = (_extract_techniques(loaded["summary"])
                      if loaded["summary"] is not None else None)
        capa_path = home / "static_analysis" / "capa.json"
        if not capa_path.exists():
            capa_path = home / "capa.json"
        capa_count = (
            capa_path.read_text(encoding="utf-8", errors="replace").count('"matches"')
            if capa_path.exists() else None)
        contributions["static"] = static_categories(
            **static_inputs, techniques=techniques, capa_match_count=capa_count)

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
