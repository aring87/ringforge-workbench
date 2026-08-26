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
from typing import Any, Iterable, Mapping, Sequence

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

#: **What the model computes**, in words that describe evidence rather than
#: interpret it. These never change meaning: `CORROBORATED` is two agreeing
#: categories or one emphatic enough to stand alone, in every module, forever.
#:
#: The interpretation is a separate step -- see `DOMAIN_VERDICTS`. Naming the
#: band for malice was wrong in a way that only showed up once two of the five
#: modules stopped assessing malice: a misconfigured API reported "Likely
#: Malicious", which is the right severity under a noun nobody would accept,
#: and an analyst who discounts that once will discount the next real one.
NOTHING_COLLECTED = "Nothing Collected"
NO_EVIDENCE = "No Evidence"
SINGLE_OBSERVATION = "Single Observation"
CORROBORATED = "Corroborated"
STRONGLY_CORROBORATED = "Strongly Corroborated"

#: Modules whose categories are **reported but not counted**, by decision.
#:
#: This is the honest middle state between *built* and *calibrated*, and the
#: dynamic side reached it first: gap 4's detector is "recorded context-only by
#: decision rather than left awaiting calibration". That was written in prose
#: and enforced by nobody. This is the same decision, in code.
#:
#: A module here still runs, still emits its whole category set, still appears
#: in coverage, and its findings still reach the page. What it cannot do is move
#: a band. The reason is recorded beside it because "why is this not counted"
#: is the first question anyone reading a report will ask.
#:
#: **Removing an entry is a claim that the module now meets the standard** --
#: that its categories have been measured against a population and separate it.
#: Nothing scores that has not been measured.
#: **Empty as of 26 Aug, and empty is a claim.** Every module in `MODULES` has
#: now been measured against a random sample of a population nobody here
#: curated, with the seed recorded. Nothing is being reported-but-not-counted,
#: because nothing is waiting on a measurement any more.
#:
#: The mechanism stays, and so do its tests. A module is added here the moment
#: one is rewritten, or a category set is changed enough that its rate is no
#: longer the rate that was measured -- which is the ordinary case, not an
#: exceptional one. `band(..., context_only=...)` takes an explicit map, so a
#: caller can hold a module without editing this file.
CONTEXT_ONLY: dict[str, str] = {}

#: **`api` was here and is not any more, 26 Aug.** It was held on the only
#: honest ground there is -- nothing had ever measured it -- and no corpus
#: existed because an HTTP response cannot be collected, only caused.
#:
#: 108 documented parameterless GETs, replayed against the servers named in the
#: spec corpus, answered 103 times. The first reading was 22.3% No Evidence:
#: three quarters of ordinary public API traffic produced a band, which is the
#: saturation this hold existed to keep out of a report. Four defects were
#: behind it -- a `Server:` header counted as a disclosure when 27 of them said
#: `cloudflare`, a wildcard CORS origin counted as a fault when it is how a
#: public API is built, a schema describing `refresh_token` read as a leaked
#: one, and a `dict` of the headers keeping one `Set-Cookie` of several.
#:
#: After them: 72.8% No Evidence, 6.8% Corroborated, nothing at the top band,
#: and the single `credential_disclosure` is a live ContentStack key returned
#: by `bungie.net/Platform/Settings/` to an unauthenticated GET. That is the
#: category doing its job on the first real population it was pointed at.

#: **`extension` was here and is not any more, 25 Aug.** It was held on a
#: measurement against the fourteen extensions installed on this bench, which
#: reported 4 of 14 at the top band and led to the conclusion that the five
#: categories were facets of one property rather than independent evidence.
#:
#: That conclusion was drawn from a biased sample. The extensions on a working
#: machine are the ones somebody chose to install, and that population skews
#: hard toward the capable. Measured against 394 randomly sampled store
#: extensions the distribution is 72.8% No Evidence, 20.1% Single Observation,
#: 6.1% Corroborated and **1.0% Strongly Corroborated** -- and the four at the
#: top band hold `debugger` with cookies across every site, or `desktopCapture`
#: with browsing history. None of them reads as a false positive.
#:
#: Kept as a comment rather than deleted because the mistake is the useful part:
#: a rate measured on a convenience sample is not a rate.

#: **`spec` was considered for this list on 26 Aug and deliberately stays out.**
#: Measured against 300 specifications sampled from APIs.guru across 300
#: distinct providers, `unauthenticated_sensitive_endpoint` is present on 32.0%
#: and emphatic on 4.0%. Of the twelve reaching the emphatic form, the members
#: include JIRA, Magento B2B, Yodlee Core APIs and Datto Autotask -- all
#: authenticated products whose published specification omits the scheme. So the
#: category is true about the document and false about the service, which is an
#: argument for holding it.
#:
#: It is not held, and the reason is what this list is for. The bar here is
#: *measured*, not *quiet*. `spec` has been measured: the rate is known in the
#: population, the wording was corrected to claim the document rather than the
#: service, and one category alone bands at Single Observation -- which is the
#: correct weight for "this document omits a control". A module whose findings
#: are true and calibrated belongs in the band even when the truth it reports is
#: uncomfortable. `api` is held because nothing has ever measured it, and that
#: is a different condition entirely.

#: Modules that assess whether an artifact is hostile, and modules that assess
#: whether a service is exposed. The distinction decides which sentence a reader
#: is shown; it changes nothing the model computes.
#:
#: A case touching both is framed as malware, because in that case the file is
#: the subject and the API it talks to is evidence about the file.
MALWARE_MODULES = frozenset({"static", "dynamic", "extension"})
POSTURE_MODULES = frozenset({"spec", "api"})

#: band -> the sentence, per domain. `Needs Review` is shared deliberately: one
#: observation with nothing corroborating it means the same thing whichever
#: question was being asked.
DOMAIN_VERDICTS: dict[str, dict[str, str]] = {
    "malware": {
        NOTHING_COLLECTED: "Insufficient Coverage",
        NO_EVIDENCE: "No Indicators Found",
        SINGLE_OBSERVATION: "Needs Review",
        CORROBORATED: "Elevated Attention",
        STRONGLY_CORROBORATED: "Likely Malicious",
    },
    "posture": {
        NOTHING_COLLECTED: "Insufficient Coverage",
        NO_EVIDENCE: "No Weaknesses Found",
        SINGLE_OBSERVATION: "Needs Review",
        CORROBORATED: "Multiple Weaknesses",
        STRONGLY_CORROBORATED: "Serious Exposure",
    },
}

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
    #: What the model computed. Stable across domains and across releases; this
    #: is the field to compare cases on, not `verdict`.
    band: str
    #: `malware` or `posture` -- which question the modules that ran were
    #: answering, and therefore which sentence `verdict` is written in.
    domain: str
    score: int
    context_score: int
    categories_present: int
    categories_strong: int
    categories_unknown: int
    coverage_complete: bool
    modules_run: tuple[str, ...] = field(default_factory=tuple)
    modules_absent: tuple[str, ...] = field(default_factory=tuple)
    #: Modules that ran and reported findings which did not count toward the
    #: band. Empty is the ordinary case; non-empty must be visible wherever the
    #: verdict is, or the page is quietly hiding observations.
    modules_context_only: tuple[str, ...] = field(default_factory=tuple)
    #: How many of their categories fired. Reported so a reader can see that
    #: "no evidence" meant "no *counted* evidence".
    context_only_present: int = 0
    context_only_names: tuple[str, ...] = field(default_factory=tuple)
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
    context_only: Mapping[str, str] | None = None,
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

    # **Reported, not counted.** Their categories stay in the list -- coverage,
    # the evidence section and the module roll-call all still see them -- and
    # they are removed from exactly one thing: the corroboration the band is
    # computed from.
    uncounted = dict(CONTEXT_ONLY if context_only is None else context_only)
    counted = [c for c in categories if c.module not in uncounted]
    context_cats = [c for c in categories
                    if c.module in uncounted and c.present]

    present = [c for c in counted if c.present]
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

    modules_context_only = tuple(sorted({c.module for c in categories
                                         if c.module in uncounted}))

    # --- The bands. Corroboration, not volume. -----------------------------
    #
    # One weak category is a single unexplained observation -- exactly what the
    # memory canary control is built to produce, and it must stay at Medium or
    # that control loses its meaning. Two agreeing categories, or one emphatic
    # enough to stand alone, is a finding.
    if not present:
        severity, band_name = "Low", NO_EVIDENCE
    elif len(present) == 1 and not strong:
        severity, band_name = "Medium", SINGLE_OBSERVATION
    elif len(present) >= 3 or len(strong) >= 2:
        severity, band_name = "High", STRONGLY_CORROBORATED
    else:
        severity, band_name = "High", CORROBORATED

    severity_floor_applied = severity == "Medium" and bool(present)
    severity_floor_reason = present[0].reason if severity_floor_applied else ""

    # **Nothing collected is not the same as nothing found.** A run in which
    # every collector failed would otherwise report the cleanest verdict this
    # model can produce, which is the project's most expensive recurring
    # mistake wearing a new hat.
    if not present and categories and not collected_any:
        severity, band_name = "Unknown", NOTHING_COLLECTED

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
        severity, band_name = "Medium", SINGLE_OBSERVATION
        dissent_floor_applied = True
        dissent_floor_reason = (
            "third-party dissent, not local evidence: our collectors did not "
            "reproduce it")

    # --- The sentence a reader is shown -------------------------------------
    #
    # Derived from the band rather than computed alongside it, so the model has
    # exactly one output and the wording can change without anything else
    # moving. The three qualifications below all narrow "nothing fired" -- none
    # of them touches a band, because a coverage gap is not evidence.
    domain = ("malware" if MALWARE_MODULES.intersection(modules_run)
              else "posture" if POSTURE_MODULES.intersection(modules_run)
              else "malware")
    verdict = DOMAIN_VERDICTS[domain][band_name]

    if band_name == NO_EVIDENCE and context_cats and not counted:
        # **The case this mechanism would otherwise get wrong.** If the *only*
        # module that ran is context-only and it found five things, banding on
        # the counted categories alone gives "No Evidence" -- which reads as
        # clean, about a case where observations were made and could not be
        # weighed. That is worse than the problem being solved.
        #
        # `not counted` is the important half. A clean, complete detonation
        # alongside one uncounted extension finding is still a clean detonation:
        # a module that *does* meet the standard looked and found nothing, and
        # downgrading that to Unknown would let an uncalibrated module veto a
        # calibrated one.
        severity = "Unknown"
        verdict = "Findings Not Scored"
    elif band_name == NO_EVIDENCE:
        if unknown:
            # **A clean headline is not available while a detector was dark.**
            # Nothing fired, and nothing firing is not a finding -- but the
            # wording has to stop short of the claim. A run with memory YARA
            # disabled that reports "Clean Baseline" has said the one thing it
            # cannot know.
            verdict = "No Findings, Coverage Incomplete"
        elif score > 10:
            verdict = "Low Suspicion"
        elif domain == "malware" and "dynamic" in modules_run:
            # **"Clean Baseline" is a claim about having watched it run.**
            # Static analysis can establish that nothing was found; it cannot
            # establish that nothing happens.
            verdict = "Benign / Clean Baseline"

    return Verdict(
        severity=severity,
        verdict=verdict,
        band=band_name,
        domain=domain,
        score=score,
        context_score=context,
        categories_present=len(present),
        categories_strong=len(strong),
        categories_unknown=len(unknown),
        coverage_complete=not unknown,
        modules_run=modules_run,
        modules_absent=modules_absent,
        modules_context_only=modules_context_only,
        context_only_present=len(context_cats),
        context_only_names=tuple(sorted(c.name for c in context_cats)),
        severity_floor_applied=severity_floor_applied,
        severity_floor_reason=severity_floor_reason,
        dissent_floor_applied=dissent_floor_applied,
        dissent_floor_reason=dissent_floor_reason,
        present_names=tuple(sorted(c.name for c in present)),
        unknown_names=tuple(sorted(c.name for c in unknown)),
    )
