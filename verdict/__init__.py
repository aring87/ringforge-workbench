"""One verdict model, shared by every analysis module.

See `docs/SCORING.md` for the decision and the mapping. Nothing consumes this
yet -- it is Phase 0, and the point of Phase 0 is that the design is still cheap
to change.
"""

from verdict.model import (
    CATEGORY_POINTS,
    CONTEXT_ONLY,
    MAX_CONTEXT_SCORE,
    MODULES,
    SCORE_MODEL,
    STRONG_CATEGORY_BONUS,
    Category,
    CategoryError,
    Verdict,
    band,
    coverage,
)

__all__ = [
    "CATEGORY_POINTS",
    "CONTEXT_ONLY",
    "MAX_CONTEXT_SCORE",
    "MODULES",
    "SCORE_MODEL",
    "STRONG_CATEGORY_BONUS",
    "Category",
    "CategoryError",
    "Verdict",
    "band",
    "coverage",
]
