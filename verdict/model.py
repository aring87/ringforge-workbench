"""The category contract and the band function -- `corroboration-v1`.

**The verdict comes from how many independent kinds of evidence agree, never
from a total.** That is not a preference; it is a measured result. The additive
model this replaces was tried on the dynamic side and could not tell a benign
memory canary (24) from live AgentTesla (60) from packed mimikatz (69) -- all
three landed in the same band, and the top band was unreachable. The score also
moved nine points between two runs of the *same control* on identical code,
purely from background noise, so any model that bands on a total is banding
partly on noise.

**This module decides nothing about malware.** It holds the shape every module
reports in, the invariants that shape has to satisfy, and the function that
turns a set of categories into a band. Authoring categories -- deciding that
three memory-only YARA rules is emphatic and two is not -- belongs to the module
that collected the evidence, because that is where the reasoning can be checked
against the data.

**Absence is not silence, and it fails at two levels.** A *module* can not have
run at all -- nobody detonated the sample -- and a *collector inside a module*
can have failed while the rest of it worked. These are different facts and a
report that conflates them will call an unanalysed sample clean:

- **Module never ran.** It emits no categories, so it appears in
  `modules_absent`. The verdict wording changes accordingly: without a
  detonation there is no "Clean Baseline" to claim.
- **Collector failed inside a module that ran.** Its categories carry
  `collected=False` and are counted as `unknown`, never as absent. `capa` with
  no ruleset, YARA with no rules directory and a FLOSS timeout each currently
  degrade into a quiet zero that reads exactly like a clean sample.

**So a module that runs emits its whole category set, absent ones included.**
That is what makes an absence mean anything, and it is what lets `modules_run`
be read off the categories rather than tracked separately and drift.

**Categories pool across modules; scores do not.** Corroboration is counted over
the union -- a static packer signature and a dynamic injection are two
independent kinds of evidence agreeing, and pooling is the only way the model
can see that. Per-module scores stay separate and descriptive, and are never
summed into a verdict; summing them is the model this one replaces.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Sequence

#: Bumped when the *meaning* of a band changes, not when a category is added.
#: `combined_score.json` carries it so a reader can tell which model produced a
#: verdict; output from before this model carries neither this nor the retired
#: `total_score`, and that absence is how you recognise it.
SCORE_MODEL = "corroboration-v1"

#: The modules allowed to author categories. A typo here would silently drop a
#: category out of per-module coverage reporting while still counting toward the
#: verdict, so it is a hard error rather than a free-form string.
MODULES = ("static", "dynamic", "spec", "api", "extension")

#: Volume is capped so background noise cannot move a band. These reproduce
#: `dynamic-corroboration-v3` exactly -- Phase 1 deletes the copies in
#: `orchestrator.py` and imports these, and `test_score_discrimination.py`
#: passing unchanged is the check that the move preserved the model.
MAX_CONTEXT_SCORE = 15
CATEGORY_POINTS = 20
STRONG_CATEGORY_BONUS = 15

#: Category names are identifiers that outlive the code that emits them: they
#: are written into `combined_score.json`, quoted in reports and compared across
#: cases. A renamed category silently splits one population into two.
_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


class CategoryError(ValueError):
    """A category that cannot mean what it claims to mean."""


@dataclass(frozen=True)
class Category:
    """One claim about the sample, from one module.

    Categories are deliberately unequal *in kind* rather than in weight -- "it
    unpacked something", "it injected", "it called home" are different
    questions, and there is no weighting to tune, which is why there is nothing
    to overfit.

    `present` is the observation. `strong` is the observation being emphatic
    enough that it needs nothing corroborating it.
    """

    name: str
    module: str
    collected: bool = True
    present: bool = False
    strong: bool = False
    detail: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if not _NAME.match(self.name or ""):
            raise CategoryError(
                f"category name {self.name!r} is not a stable identifier "
                f"(lowercase, digits and underscores). Names are written into "
                f"reports and compared across cases; a renamed one splits a "
                f"population in two without any error."
            )
        if self.module not in MODULES:
            raise CategoryError(
                f"{self.name}: module {self.module!r} is not one of {MODULES}. "
                f"An unrecognised module would drop this category out of "
                f"coverage reporting while it still counted toward the verdict."
            )
        if self.present and not self.collected:
            raise CategoryError(
                f"{self.name}: present but not collected. A collector that did "
                f"not run cannot have observed anything -- if it ran and found "
                f"nothing, that is collected=True, present=False."
            )
        if self.strong and not self.present:
            raise CategoryError(
                f"{self.name}: strong but not present. Strong is a property of "
                f"an observation, not a substitute for one."
            )
        if self.present and not (self.reason or "").strip():
            raise CategoryError(
                f"{self.name}: present with no reason. The reason *is* the "
                f"rationale the report prints; a verdict built from categories "
                f"nobody can explain is the additive model with extra steps."
            )


@dataclass(frozen=True)
class Verdict:
    """The band, and everything needed to argue with it."""

    severity: str
    verdict: str
    score: int
    context_score: int
    categories_present: int
    categories_strong: int
    categories_unknown: int
    coverage_complete: bool
    modules_run: tuple[str, ...] = field(default_factory=tuple)
    modules_absent: tuple[str, ...] = field(default_factory=tuple)
    severity_floor_applied: bool = False
    severity_floor_reason: str = ""
    dissent_floor_applied: bool = False
    dissent_floor_reason: str = ""
    score_model: str = SCORE_MODEL
    present_names: tuple[str, ...] = field(default_factory=tuple)
    unknown_names: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _check_unique(categories: Sequence[Category]) -> None:
    """A category fires at most once, however many events back it.

    This is the whole defence against volume. Emitting `stripped_metadata`
    four times because four version-info fields were missing is the additive
    model reappearing under a new name -- one chatty behaviour outvoting three
    quiet ones. Duplicates are a coding error, so they raise here rather than
    being silently collapsed, which would hide the bug that produced them.
    """
    seen: set[tuple[str, str]] = set()
    for category in categories:
        key = (category.module, category.name)
        if key in seen:
            raise CategoryError(
                f"{category.module}/{category.name} reported twice. A category "
                f"fires once however many events back it; report the count in "
                f"`detail` instead."
            )
        seen.add(key)


def coverage(categories: Iterable[Category]) -> dict[str, dict[str, Any]]:
    """Per-module collection state, for the report to render honestly.

    Kept separate from the verdict because it answers a different question:
    not *what did we find* but *what were we able to look for*.
    """
    out: dict[str, dict[str, Any]] = {}
    for category in categories:
        entry = out.setdefault(
            category.module, {"collected": [], "uncollected": []})
        entry["collected" if category.collected else "uncollected"].append(
            category.name)
    for entry in out.values():
        entry["collected"] = sorted(entry["collected"])
        entry["uncollected"] = sorted(entry["uncollected"])
        entry["complete"] = not entry["uncollected"]
    return out


def band(
    categories: Sequence[Category],
    context_score: int = 0,
    third_party_dissent: bool = False,
) -> Verdict:
    """Turn a set of categories into a band.

    `context_score` is descriptive volume -- how much happened. It is capped and
    it never decides a band; it exists so two runs in the same band can still be
    told apart.

    `third_party_dissent` is a decision made by the caller, not here: this
    module deliberately does not know VirusTotal's thresholds, because the
    moment it does, the thresholds start being tuned to move verdicts.
    """
    categories = list(categories)
    _check_unique(categories)

    present = [c for c in categories if c.present]
    strong = [c for c in present if c.strong]
    unknown = [c for c in categories if not c.collected]
    collected_any = any(c.collected for c in categories)

    # **Which modules ran is read from the categories themselves**, which only
    # works because of the contract stated above: a module that ran emits its
    # whole category set, absent ones included. That is what makes an absence
    # mean something, and it makes the output self-describing -- there is no
    # second list to keep in step with the first.
    modules_run = tuple(sorted({c.module for c in categories}))
    modules_absent = tuple(m for m in MODULES if m not in modules_run)

    context = max(0, min(MAX_CONTEXT_SCORE, int(context_score)))
    score = (context
             + len(present) * CATEGORY_POINTS
             + len(strong) * STRONG_CATEGORY_BONUS)

    # --- The bands. Corroboration, not volume. -----------------------------
    #
    # One weak category is a single unexplained observation -- exactly what the
    # memory canary control is built to produce, and it must stay at Medium or
    # that control loses its meaning. Two agreeing categories, or one emphatic
    # enough to stand alone, is a finding.
    if not present:
        severity = "Low"
        if score > 10:
            verdict = "Low Suspicion"
        elif "dynamic" in modules_run:
            verdict = "Benign / Clean Baseline"
        else:
            # **"Clean Baseline" is a claim about having watched it run.**
            # Static analysis can establish that nothing was found; it cannot
            # establish that nothing happens. Saying otherwise is how a sample
            # nobody detonated ends up filed as clean.
            verdict = "No Indicators Found"
    elif len(present) == 1 and not strong:
        severity, verdict = "Medium", "Needs Review"
    elif len(present) >= 3 or len(strong) >= 2:
        severity, verdict = "High", "Likely Malicious"
    else:
        severity, verdict = "High", "Elevated Attention"

    severity_floor_applied = severity == "Medium" and bool(present)
    severity_floor_reason = present[0].reason if severity_floor_applied else ""

    # **Nothing collected is not the same as nothing found.** A run in which
    # every collector failed would otherwise report the cleanest verdict this
    # model can produce, which is the project's most expensive recurring
    # mistake wearing a new hat.
    if not present and categories and not collected_any:
        severity, verdict = "Unknown", "Insufficient Coverage"

    # **The dissent floor.** Removing VirusTotal from the verdict removes an
    # override that used to exist, and without a replacement a file 60 of 70
    # engines call malicious reports Benign next to a screaming VT panel.
    # Floors at Needs Review and goes no higher -- there is no path from a
    # third-party opinion to Elevated Attention or Likely Malicious, because
    # somebody else's conclusion about the same file is not a second kind of
    # evidence.
    dissent_floor_applied = False
    dissent_floor_reason = ""
    if third_party_dissent and severity in ("Low", "Unknown"):
        severity, verdict = "Medium", "Needs Review"
        dissent_floor_applied = True
        dissent_floor_reason = (
            "third-party dissent, not local evidence: our collectors did not "
            "reproduce it")

    return Verdict(
        severity=severity,
        verdict=verdict,
        score=score,
        context_score=context,
        categories_present=len(present),
        categories_strong=len(strong),
        categories_unknown=len(unknown),
        coverage_complete=not unknown,
        modules_run=modules_run,
        modules_absent=modules_absent,
        severity_floor_applied=severity_floor_applied,
        severity_floor_reason=severity_floor_reason,
        dissent_floor_applied=dissent_floor_applied,
        dissent_floor_reason=dissent_floor_reason,
        present_names=tuple(sorted(c.name for c in present)),
        unknown_names=tuple(sorted(c.name for c in unknown)),
    )
