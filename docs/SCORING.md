# One verdict model, across every module

Written 24 Aug 2026. Scope is the *verdict*: how `static_triage_engine`,
`dynamic_analysis`, the API spec analyser and the extension analyser combine
into one answer a reader can defend. It is a design note, not a plan of record
— nothing here has been built yet, and the mapping below is the thing to argue
with before any of it is.

---

## The decision

**Every module reports evidence categories. The verdict comes from
corroboration across them, never from a total.** The model is the one already
running in `dynamic_analysis/orchestrator.py` as `dynamic-corroboration-v3`,
generalised to cover the other modules and renamed `corroboration-v1` once it
does.

The additive point model in `static_triage_engine/scoring.py` is retired. It is
not being re-thresholded, and none of its caps survive.

### Why this one

**Because the additive model was already tried on the dynamic side and
measurably failed.** The comment that replaced it records the numbers: a benign
memory canary scored 24, live AgentTesla 60, packed mimikatz 69 — and all three
landed in the same band, while "High" at >120 was unreachable. A scale that
cannot separate a control from a credential stealer is not a scale, and adding
static points to it would not have fixed that.

**Because the verdict has to survive a question.** "Four categories, two of them
strong" can be read aloud and defended. "Score 30" cannot, and it is worse than
useless when the reader asks *thirty out of what, and why is that the line*.

**Because corroboration resists volume.** A category fires at most once however
many events back it. Under the additive model one chatty behaviour outvotes
three quiet ones, which is how a file-writing installer outscores a quiet
implant.

**Because it already distinguishes silence from absence.** The dynamic model's
own notes say it: *absence of a category means it was not observed, which is not
the same as it not happening*. That is this project's governing rule everywhere
else, and the static engine currently has no way to express it.

### What the current code actually does, for the record

Three things are wrong today, and they are wrong in ways that produce answers
rather than errors:

- **`calculate_combined_score` sums three sub-scores and clamps to 100.** Static
  caps at 40, dynamic at 30, spec at the rest.
- **`classify_verdict` mixes two scales inside one function.** Its bands are
  `LOW_RISK=8 / SUSPICIOUS=20 / MALICIOUS=30`, derived for the 0–40 static
  scale, but it is called on the 0–100 combined total — so `MALICIOUS` fires at
  30 of 100. The VirusTotal branches in the same function test `score >= 50` and
  `score >= 75`, which only make sense on the other scale.
- **`score_dynamic` re-scores the dynamic module's findings on its own 0–30
  scale.** The corroboration model's output is flattened back into additive
  points on the way into the combined score, which is the exact reasoning this
  note exists to stop.

---

## The category contract

One shape, emitted by every module.

    name       stable identifier; never renamed once it has been reported
    module     static | dynamic | spec | api | extension
    collected  did the collector behind this category actually run
    present    the observation happened
    strong     emphatic enough that it needs no corroboration
    detail     one factual line; counts belong here
    reason     prose saying what it means; empty when not present

### Four rules that make it work

**A category fires at most once, however many events back it.** This is the
whole defence against volume. Four separate "missing version-info field" points
are not four kinds of evidence; they are one claim with four facets.

**Categories are unequal in kind, not in weight.** "It unpacked something", "it
injected", "it installed persistence", "it called home" are different questions.
There is no weighting to tune, which is why there is nothing to overfit.

**`collected` is not `present`.** This is the field the dynamic model did not
need and the static engine cannot do without. `capa` with no ruleset, YARA with
no rules directory, a `FLOSS` timeout — each currently degrades into a quiet
zero that reads as a clean sample. A category whose collector did not run is
`collected: false`, and it is reported as **unknown**, never counted as absent.

**Absence is only meaningful from a collector shown capable of a positive.**
Same standard the detonation bench runs under. A module reporting all-absent
with no positive control behind it is reporting nothing.

### The bands, unchanged

    no category present            Low     Benign / Clean Baseline
                                           (Low Suspicion if context > 10)
    one present, none strong       Medium  Needs Review
    two present, or one strong     High    Elevated Attention
    three present, or two strong   High    Likely Malicious

The single-category floor is deliberate and load-bearing: it is where the benign
memory canary lands, and moving it would cost that control its meaning.

A **score is still emitted** — context points, capped — but it is a description,
not a verdict input. Nothing bands on it.

### Two more bands, both about not having looked

    nothing collected at all       Unknown  Insufficient Coverage
    no category present, and
      dynamic never ran            Low      No Indicators Found

The first exists because a run in which every collector failed would otherwise
produce the *cleanest* verdict the model can express.

The second is narrower and worth stating plainly: **"Clean Baseline" is a claim
about having watched the sample run.** Static analysis can establish that
nothing was found; it cannot establish that nothing happens. A static-only case
that says "Benign / Clean Baseline" is how a sample nobody detonated ends up
filed as clean.

### Scores stay separate; categories pool

Two different questions, and conflating them is what the current combiner does.

**Categories pool across modules.** Corroboration is counted over the union — a
static packer signature and a dynamic injection are two independent kinds of
evidence agreeing, and only the union can see that. Scoring each module
separately and comparing the numbers would throw away the single most useful
thing this model does.

**Per-module scores stay separate and descriptive.** They say how much happened
in each module. They are never summed into a verdict; summing them is precisely
the model being replaced.

### "Was this analysis run" fails at two levels

They are different facts and a report that conflates them will call an
unanalysed sample clean:

- **A module never ran.** It emits no categories and appears in
  `modules_absent`. This is what changes the Low-band wording above.
- **A collector failed inside a module that did run.** Its categories carry
  `collected: false` and count as *unknown*. `capa` with no ruleset, YARA with
  no rules directory, a FLOSS timeout.

So **a module that runs emits its whole category set, absent ones included.**
That is what makes an absence mean anything, and it lets `modules_run` be read
off the categories rather than tracked in a second list that drifts from the
first.

---

## Mapping every current path

### `dynamic_analysis` — already there

Emits categories today. The work is lifting the shape into a shared module and
adding `collected`, which the run already knows from its telemetry-coverage
warnings but does not attach per category.

### `static_triage_engine.score_static` → categories

The current rules are additive facets. Grouped into claims:

| Current evidence rules | Becomes | Strong when |
|---|---|---|
| `missing_company`, `missing_product`, `missing_description`, `missing_original_filename` | `stripped_metadata` | all four absent |
| `hash_like_name`, `suspicious_extension` | `deceptive_file_identity` | double extension, or RLO |
| YARA matches | `known_malware_signature` | a family-named rule, or 3+ distinct |
| API findings | `dangerous_capability` | 2+ high-signal groups |
| Authenticode result | `invalid_signature` | present but broken, which is worse than absent |
| IOC extraction | `embedded_network_indicators` | non-benign host with a hardcoded path |
| `capa_density` | **context score only** | — never a category |
| `yara_incomplete`, `api_analysis_incomplete` | **`collected: false`** on the categories they cover | — |

Note what the last two rows do. `capa_density` is volume by definition and
becomes context. The two `_incomplete` rules already exist because someone hit
this problem and expressed it as a score adjustment; under the contract they
become coverage state, which is what they always were.

### VirusTotal is not a category

**Deliberate, and the most arguable call here.** The model's premise is that
independent kinds of evidence agree. A VirusTotal verdict is not independent
evidence — it is other people's conclusion about the same file. Counting it as a
category lets the model claim corroboration it did not earn, and it would let a
sample reach "Likely Malicious" on one local observation plus somebody else's
opinion.

VT stays, reported prominently, and it moves **confidence** rather than
presence. A high VT count against a single local category says *the reader
should look harder*, not *three things agreed*.

#### The dissent floor

Removing VT from the verdict removes an override that exists today:
`classify_verdict` currently forces `MALICIOUS` on a strong VT count regardless
of local evidence. Without a replacement, a file with 60 of 70 engines calling
it malicious, where our own collectors found nothing, reports **Benign / Clean
Baseline** next to a screaming VT panel. That is technically honest and nobody
will accept it, correctly.

So: **when VT is strongly malicious and the local band is below Needs Review,
the band floors at Needs Review**, with the reason recorded as *third-party
dissent, not local evidence*. It is named separately from the category floor so
the two can never be read as the same thing, and it is capped — there is no path
from VirusTotal to Elevated Attention or Likely Malicious, ever.

`Needs Review` already means *one unexplained observation with nothing
corroborating it*. A VT hit our collectors cannot reproduce is exactly that, and
the floor keeps the honest reading in front of the analyst: we found nothing and
someone else found something.

**The floor is also a bench-defect detector**, which is why it earns its place
rather than merely patching an embarrassment. A sample sitting at Needs Review
*because of* the dissent floor is a sample our collectors failed on. That
population is worth a report of its own.

### `score_spec` → categories

`no_auth` and `sensitive_unauth` collapse into `unauthenticated_sensitive_endpoint`
(the second being the strong form of the first, not a separate claim).
`destructive_admin` → `destructive_admin_surface`. `file_uploads` →
`unrestricted_upload`. `http_server` → `plaintext_transport`.

### `api` and `extension`

Not yet examined. They must land on the same contract before the combiner is
called finished, and until they do they report `collected: false` rather than
contributing silence.

---

## What breaks

Named up front, because the reason this note exists is to find out before the
edit rather than after.

1. **`calculate_combined_score` sum-and-clamp is deleted.** Every consumer
   reading `total_score` as 0–100 changes meaning.
2. **`classify_verdict` is deleted.** Its VT logic is re-expressed as confidence.
   Its thresholds have no successor.
3. **`score_dynamic` in `scoring.py` is deleted, not ported.** The dynamic module
   emits categories; the combiner consumes them directly. This removes an entire
   re-scoring path rather than migrating it.
4. **`combined_score.json` changes shape.** Consumers: `gui/unified_report_window.py`,
   `static_triage_engine/report.py`, `dynamic_analysis/html_report.py`, and
   `combined_score_from_case_dir` — which also carries dual old/new case-layout
   support that should die in the same pass.
5. **The verdict vocabulary unifies.** `MALICIOUS` / `SUSPICIOUS` / `LOW_RISK` /
   `BENIGN` retire in favour of the four bands. Nineteen files reference verdict
   strings today; each needs checking, and a test should pin that the retired
   strings appear nowhere.
6. **`verdict_rationale.py` is rewritten against categories.** It gets easier —
   the `reason` field is the rationale, already written per category.
7. **Static's `STATIC_SCORE_MAX = 40` and its three thresholds retire.**

Nothing above is reversible by config, so `combined_score.json` carries
`score_model: "corroboration-v1"` and the old writer stays for one release
emitting both. A reader that finds neither field is reading output from before
this note.

---

## Sequence

**Phase 0 — the contract.** A single module defining the category dataclass, the
band function, and the JSON schema, with tests. Nothing consumes it yet. This is
the only phase where the design can still be changed cheaply.

**Phase 1 — dynamic emits the shared shape.** Mostly a lift. `test_score_discrimination.py`
must pass unchanged against the new emitter, since it encodes the bands that are
being preserved — if it needs editing, the model changed and that is a finding.

**Phase 2 — static authors its categories, with coverage state.** Gated on a
discrimination test that does not exist yet. Static currently has **two tests
against 6,518 lines**, one of which only asserts return types. That test is the
deliverable of this phase; the categories are how it passes.

Method, copied from `test_score_discrimination.py` rather than invented: that
test calls the scorer directly with synthetic inputs and encodes the *contract*
— the benign canary must stay at Needs Review — instead of replaying recorded
runs. Do the same here. That matters practically as well as aesthetically. **The
sample binaries are not on this host**, and only two case folders survive
locally, neither of them ground truth, so a test built on committed fixture
blobs could not be written today. A test built on the contract can, and it keeps
running after the next sample is re-acquired or lost.

The contract to encode, at minimum: a signed vendor installer with clean
metadata reaches no category; a hash-named unsigned binary with stripped
version-info reaches exactly one and stays at Needs Review; a family-named YARA
hit alongside a dangerous API capability reaches Elevated Attention; and a capa
run with no ruleset reports **unknown** rather than contributing an absence.

**Phase 3 — spec, api, extension.** Same contract, `collected: false` until each
is genuinely wired.

**Phase 4 — the combiner, the report, and the theme.** One verdict to display
makes the unified report a design problem instead of a reconciliation problem.
The theme work belongs here and not earlier: `gui/theme.py` (40 colours) and
`dynamic_analysis/report_theme.py` (17 colours) currently share **zero** values,
and 37 hardcoded hex colours bypass the theme in four windows. One source, both
media derived from it, and a test asserting no literal hex outside it.

---

## The standard, borrowed from `docs/ROADMAP.md`

> Every category has fired at least once on real data, or is explicitly recorded
> as never having fired and why. Nothing contributes to a verdict that has not
> been measured. Nothing reads as absent when it was never collected.

Applied to the verdict model, that is the definition of done for all four
phases.
