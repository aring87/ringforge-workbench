"""One verdict from every module that ran -- `corroboration-v1`.

Phase 4a of `docs/SCORING.md`. This replaces `scoring.calculate_combined_score`,
which summed a 0-40 static score, a 0-30 dynamic score and a spec score, clamped
the total to 100, and then banded it with thresholds derived for the 0-40 scale.
`MALICIOUS` fired at 30 of 100 while the VirusTotal branches in the same function
tested 50 and 75.

**Categories pool; scores do not.** Corroboration is counted over the union of
every module's categories, because that is the only way the model can see a
static packer signature and a dynamic injection as two independent kinds of
evidence agreeing. Per-module scores are carried through as description and are
never added together -- adding them is the model being replaced.

**This module stays pure.** It takes categories that somebody else built and
knows nothing about case directories, file layouts or VirusTotal thresholds.
`static_triage_engine.combine_case` is the part that reads a case off disk, and
it is separate precisely so that the thing deciding the verdict can be tested
without one.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from verdict.model import (
    CONTEXT_ONLY,
    SCORE_MODEL,
    Category,
    band,
    coverage,
)


class Contribution:
    """One module's categories and its descriptive score.

    A thin holder rather than a dataclass so callers can pass a plain tuple; the
    combiner accepts either.
    """

    __slots__ = ("categories", "context_score")

    def __init__(self, categories: Sequence[Category], context_score: int = 0):
        self.categories = list(categories)
        self.context_score = int(context_score or 0)


def _as_contribution(value: Any) -> Contribution:
    if isinstance(value, Contribution):
        return value
    if isinstance(value, tuple) and len(value) == 2:
        return Contribution(value[0], value[1])
    return Contribution(value or [], 0)


def category_from_dict(raw: Mapping[str, Any]) -> Category:
    """Rebuild a `Category` from serialised JSON.

    Modules that ran in another process -- a detonation, most of the time --
    reach the combiner through their summary file rather than in memory. The
    invariants still apply on the way back in: a summary claiming a category is
    present with no reason is rejected here rather than producing a verdict
    nobody can explain.
    """
    return Category(
        name=str(raw.get("name", "")),
        module=str(raw.get("module", "")),
        collected=bool(raw.get("collected", True)),
        present=bool(raw.get("present", False)),
        strong=bool(raw.get("strong", False)),
        detail=str(raw.get("detail", "") or ""),
        reason=str(raw.get("reason", "") or ""),
    )


def categories_from_json(entries: Iterable[Mapping[str, Any]] | None) -> list[Category]:
    """Rebuild a module's whole category set, skipping anything unreadable.

    A malformed entry is dropped rather than raising: one bad row in a summary
    written months ago should not make a case unreadable. Everything dropped is
    simply absent from the pool, which the coverage report then shows.
    """
    out: list[Category] = []
    for raw in entries or []:
        if not isinstance(raw, Mapping):
            continue
        try:
            out.append(category_from_dict(raw))
        except Exception:
            continue
    return out


def combine(
    contributions: Mapping[str, Any],
    third_party_dissent: bool = False,
    dissent_detail: str = "",
) -> dict[str, Any]:
    """Pool every module's categories and band once.

    `contributions` maps a module name to either a `Contribution` or a
    `(categories, context_score)` tuple. A module that did not run is simply
    absent from the mapping -- **not** present with an empty list, which would
    claim it ran and found nothing.

    `third_party_dissent` is decided by the caller. This module does not know
    what VirusTotal is, and keeping it that way is what stops a third-party
    threshold from being quietly tuned until it moves verdicts.
    """
    pooled: list[Category] = []
    subscores: dict[str, int] = {}

    for module, value in (contributions or {}).items():
        contribution = _as_contribution(value)
        pooled.extend(contribution.categories)
        subscores[module] = contribution.context_score

    result = band(pooled, context_score=sum(subscores.values()),
                  third_party_dissent=third_party_dissent)

    present = [c for c in pooled if c.present]
    strong = [c for c in present if c.strong]

    return {
        "score_model": SCORE_MODEL,
        "severity": result.severity,
        # **The band is what the model computed; the verdict is the sentence.**
        # Compare cases on `band` -- it is stable across domains and releases.
        # `verdict` is written for a reader and its wording follows the domain,
        # so the same band reads "Likely Malicious" for a sample and "Serious
        # Exposure" for an API.
        "band": result.band,
        "domain": result.domain,
        "verdict": result.verdict,
        # Descriptive. Nothing bands on it, and it is not the sum of the
        # per-module scores in any meaningful sense -- it is capped volume plus
        # what the categories contributed.
        "score": result.score,
        "context_score": result.context_score,
        "subscores": subscores,
        "modules_run": list(result.modules_run),
        "modules_absent": list(result.modules_absent),
        # Reported but not counted -- see `CONTEXT_ONLY`. Non-empty means the
        # page must show these findings and say they did not move the band.
        "modules_context_only": list(result.modules_context_only),
        "context_only": {
            "present": result.context_only_present,
            "names": list(result.context_only_names),
            "reasons": {m: CONTEXT_ONLY[m] for m in result.modules_context_only
                        if m in CONTEXT_ONLY},
        },
        "counts": {
            "categories_present": result.categories_present,
            "categories_strong": result.categories_strong,
            "categories_unknown": result.categories_unknown,
        },
        "coverage_complete": result.coverage_complete,
        "coverage": coverage(pooled),
        "uncollected_categories": list(result.unknown_names),
        # The evidence, in the order the reader should meet it: emphatic first,
        # then the rest, each carrying the prose that explains it.
        "evidence": [
            {
                "name": c.name,
                "module": c.module,
                "strong": c.strong,
                "detail": c.detail,
                "reason": c.reason,
            }
            for c in sorted(present, key=lambda c: (not c.strong, c.module, c.name))
        ],
        "severity_floor_applied": result.severity_floor_applied,
        "severity_floor_reason": result.severity_floor_reason,
        "dissent_floor_applied": result.dissent_floor_applied,
        "dissent_floor_reason": (dissent_detail or result.dissent_floor_reason)
        if result.dissent_floor_applied else "",
    }
