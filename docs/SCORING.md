# One verdict model, across every module

Written 24 Aug 2026. Scope is the *verdict*: how `static_triage_engine`,
`dynamic_analysis`, the API spec analyser and the extension analyser combine
into one answer a reader can defend.

**Written as a design note before any of it existed; now a record of what was
built.** Phases 0 through 4b are done and marked so below. The reasoning is left
as it was written — including the two places the design was wrong and the tests
said so — because how a decision was reached outlasts the decision.

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

### Three more verdicts, all about not having looked

    nothing collected at all       Unknown  Insufficient Coverage
    nothing fired, but some
      collector was dark           Low      No Findings, Coverage Incomplete
    nothing fired, and
      dynamic never ran            Low      No Indicators Found

The first exists because a run in which every collector failed would otherwise
produce the *cleanest* verdict the model can express.

The second keeps the band and withdraws the claim. Nothing fired, and nothing
firing is not a finding — so `Low` is right. But a run whose packer detector was
switched off has not earned the words *Clean Baseline*, because the detector
that would have disagreed was never asked. Coverage gaps qualify a clean result
and say nothing about a category that did fire; a finding stands regardless of
what else was dark.

The third is narrower and worth stating plainly: **"Clean Baseline" is a claim
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
| `missing_company`, `missing_product`, `missing_description`, `missing_original_filename` | `stripped_metadata` | **never** — see below |
| `suspicious_extension` | `deceptive_file_identity` | double extension, or RLO |
| `hash_like_name` | **deleted** — see below | — |
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

**Phase 1 — dynamic emits the shared shape. DONE, 24 Aug.**
`test_score_discrimination.py` passed unchanged — 29 tests, file untouched,
which is the record that the bands survived the move rather than being
renegotiated during it.

`orchestrator.py` now imports the constants and `band()` from `verdict/` instead
of defining its own, and builds `verdict.Category` objects. What stayed local is
authoring: `STRONG_MEMORY_ONLY_RULES = 3` is a judgement checked against
mimikatz.upx (five rules) and live AgentTesla (three), and it belongs next to
that data.

The lift also forced the coverage question the dynamic side had never had to
answer. `CATEGORY_SOURCES` maps each category to the run summaries that can make
it fire, so `available: False` on a summary becomes `collected: False` on its
categories. `test_category_coverage.py` pins it, including a drift check —
a category added without a line in that map would default to collected forever
and claim coverage it never had, silently, in the direction that makes samples
look clean.

Writing that test is what exposed the missing verdict above: a run with memory
YARA disabled was still reporting **Benign / Clean Baseline**.

**Phase 2 — static authors its categories, with coverage state. DONE, 24 Aug.**
`static_triage_engine/categories.py` emits six categories against the shared
contract, and `test_static_discrimination.py` encodes what they have to
separate. Static went from **two tests against 6,518 lines** to **36**.

Written alongside `scoring.py` rather than replacing it: nothing consumes the
new emitter until Phase 4, so the additive scorer stays live and the GUI keeps
working. Everything is injected — no case-directory reads — which is what makes
a six-line contract test possible.

**Three things the rewrite found in the live scorer.** All three are false
positives, all three are silent, and none of them would have been visible from
reading the additive code:

1. **A hash-like filename charged 6 points**, and this pipeline acquires
   samples by hash and stores them under it. Every sample it has ever
   downloaded started six points up. The on-disk name is what the *analyst*
   called the file; the author's claim about the name is `OriginalFilename`,
   which the version-info category already covers. Deleted, not ported.
2. **An empty version-info block would have stood alone.** Marked strong at
   first, which put it at Elevated Attention by itself — sweeping up Go and
   Rust binaries and anything built without a resource script. `stripped_metadata`
   now corroborates and never concludes.
3. **Being unsigned was worth 8 points.** Most malware is unsigned and so is
   most small legitimate tooling; the absence of exculpatory evidence is not
   incriminating evidence. A signature that is *present and does not verify* is
   a different claim, and that is what became the category.

The pattern is the same each time: the additive model priced things it could
not justify, and pricing hid the fact that it could not justify them. Asking
"what claim is this, and does it stand alone" is a harder question to answer
and a much harder one to get wrong quietly.

Only three of the six static categories can ever be strong —
`known_malware_signature`, `dangerous_capability`, `deceptive_file_identity`.
The other three corroborate only.

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

**Phase 3a — spec. DONE, 24 Aug.** Four categories in `categories.py`, 21 tests
in `test_spec_discrimination.py`, against a scorer that had none. Reading it
with Phase 2's question found three more defects of the same shape:

1. **An unparseable spec scored 10 of 30 for having no authentication.** The
   test was `auth_scheme_count == 0`, which is true of an empty dict, a spec
   that failed to parse, and a file that was never a spec. Missing data read as
   a finding, which is the error the whole model exists to stop. Categories are
   now gated on the analysis having run *and* the document describing at least
   one endpoint.
2. **`no_auth` and `sensitive_unauth` were one claim charged twice.**
   `sensitive_unauth` required `auth_scheme_count == 0`, one of the conditions
   that made `no_auth` true — so an unauthenticated admin route scored on both,
   up to 18 of a 30-point ceiling. Collapsed: the admin case is the strong form
   of the same category.
3. **`http://localhost:8080` cost 6 points.** A spec listing a loopback or
   private-network server is describing a development environment.
   `plaintext_transport` now exempts loopback, RFC1918 and `.local`/`.internal`
   hosts.

And one the rewrite changed rather than found: `destructive_admin_surface` is
about the **exemption**, not the existence. `DELETE /admin/users/{id}` is how a
correct admin API is built. What is a finding is a spec that declares
authentication and then exempts a destructive administrative route from it —
which also keeps the category independent of the one above, so an API with no
auth cannot corroborate itself.

**Phase 3b — extension. DONE, 24 Aug. api still to do.**

Not the rename this note assumed: `gui/extension_window.py` (1,743 lines) and
`gui/api_window.py` (1,394) performed their analysis inside Tkinter windows,
importing nothing but the theme. Neither could emit categories until the logic
was extracted, which is also why neither had a test.

`static_triage_engine/extension_analysis.py` now holds the extension half, with
26 tests, and the window draws what it decides. Five categories:
`broad_host_access`, `high_risk_permission`, `credential_surface`,
`dynamic_code_execution`, `external_control_surface`.

**The scorer it replaced was saturated, which is worse than wrong.** It summed
weighted permissions, manifest features and source-pattern hits toward 100 and
called 80 `Critical` — and the source scan added its points **once per file**.
`fetch(` was worth 5 in every file containing it, `https://` one, and
`XMLHttpRequest` five. Measured on a nine-file package with a jQuery bundle and
no malicious behaviour: **67 from the source scan alone**, plus 43 from the
manifest terms for broad hosts, content scripts and a background worker. Every
non-trivial extension in existence rated `Critical`. A verdict that is the same
for everything is not a verdict.

The fix is not a reweighting. **A pattern fires once however many files contain
it**, and the file count moves to `detail` where a reader can weigh it —
counting occurrences is precisely what a corroboration model does not do. The
same package now reads `Low`, and a session-stealer shape reaches
`Likely Malicious` on five categories.

One place this module departs from the dynamic side deliberately: a category
that reads both the manifest and the source tree is `collected` only when
**both** ran. The dynamic module counts *any* of its telemetry routes as enough,
because those are three views of one behaviour. Here they are not — the manifest
says what an extension *requests* and the source says what it *uses*, and an
extension asking for nothing while its code reads cookies is exactly the case
worth catching.

**Phase 4a — the combiner. DONE, 24 Aug.** 38 tests across
`verdict/tests/test_combine.py` and `static_triage_engine/tests/test_combine_case.py`.

Split in two, and the split is the point:

- **`verdict/combine.py` is pure.** It pools categories, bands once, and emits
  the JSON shape. It knows nothing about case directories, file layouts or
  VirusTotal — so the thing that decides the verdict can be tested without
  building a case folder, which is exactly what the old combiner could not do.
- **`static_triage_engine/combine_case.py` reads disk.** Case layout, both
  historical folder shapes, and the VirusTotal thresholds live here. Those
  thresholds are deliberately *outside* `verdict/`: the moment the module that
  decides bands also knows what VirusTotal is, its numbers start being tuned to
  move verdicts.

**Nothing is deleted yet.** The additive `combined_score.json` keeps being
written by the old path, and the new verdict goes to `combined_verdict.json`
beside it. A shape change and a consumer migration in one commit would leave no
working state to bisect back to; Phase 4b moves the consumers and then deletes.

**Dynamic categories are rebuilt from the run summary, not recomputed.** The run
happened in another process on another machine, so `calculate_dynamic_score` now
serialises its whole category set under `score_detail.categories` — absent and
uncollected ones included, because pooling is only meaningful if each module
says what it *looked for*. The contract invariants are re-applied on the way
back in: a summary claiming a category is present with no reason is dropped
rather than trusted, and one unreadable row does not make a months-old case
unreadable.

**The dissent threshold is five engines.** One or two is the noise floor of
multi-engine scanning — `_is_weak_vt_noise` already encoded that — and a floor
firing there would move a large fraction of ordinary software to Needs Review
and teach everyone to ignore the band.

**Phase 4b — the report and the theme. DONE, 24 Aug.** Two commits.

*The theme.* `design_tokens.py` holds the palette and depends on nothing;
`gui/theme.py` re-exports it so the twelve GUI modules needed no changes, and
`report_theme.report_css()` is built from the same values. The "37 hardcoded hex
colours" turned out to be **five report stylesheets** — this one, two
near-identical copies, and two ad-hoc sheets with entirely different palettes.
All four copies now call the shared sheet; the rules they had and it lacked
(`.sev-critical`, `pre`, `.label`) were folded in. 457 lines and 6,305
characters of duplicated CSS gone.

*The verdict.* `engine.py` writes a corroboration band into `summary.json`
instead of `score_risk` + `classify_verdict`. `report.py` and
`unified_report_window` read `combined_verdict.json`, and the two GUI call sites
that invoked the old writer for its side effect now call `combine_case`.

*The deletions.* `scoring.py` went from **1,150 lines to 274** — the additive
model is gone, and what remains is the helpers that never had anything to do
with scoring, which the new code imports rather than reimplementing.
`test_scoring.py` went with it: its two tests covered a function that no longer
exists, and `test_static_discrimination.py` replaced them with 34.

Two things worth recording. The "19 files referencing retired verdict strings"
was a false alarm — all but two were unrelated constants like
`SUSPICIOUS_PATH_HINTS`. The two real ones were in `report.py`, and one of them
tested for `MEDIUM_RISK`, a verdict `classify_verdict` never produced. And its
sibling branch tested `score < 60` against a scale whose maximum was 40, so it
could never fire on its own terms while the `score < 45` branch always did.

`verdict_rationale.py` got shorter, because the categories already carry prose
written to be read aloud — it quotes them now rather than re-deriving a parallel
set of sentences that could disagree with the verdict beside them. Three of its
premises retired with the additive model, including *"file is unsigned"* as a
reason a score went up.

---

## The standard, borrowed from `docs/ROADMAP.md`

> Every category has fired at least once on real data, or is explicitly recorded
> as never having fired and why. Nothing contributes to a verdict that has not
> been measured. Nothing reads as absent when it was never collected.

Applied to the verdict model, that is the definition of done for all four
phases.
