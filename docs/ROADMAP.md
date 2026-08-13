# Roadmap

Written 13 Aug 2026, to answer three questions: what is actually in this
program, is the dynamic side finished enough to leave, and what does moving to
static and the API workflows involve.

`README.md` has a roadmap already. It is a feature wishlist — fifteen bullets,
unranked, no statement of risk. This is the other kind: what is load-bearing,
what is untested, and what order the work wants doing in.

---

## What the program is

Six workflows over one case-folder model, across roughly 47,000 lines of Python:

| Area | Lines | Test files | Tests |
|---|---:|---:|---:|
| `dynamic_analysis/` | 27,122 | 46 | **550** fast, 564 with `slow` |
| `gui/` | 13,667 | 0 | 0 |
| `static_triage_engine/` | 6,419 | 1 | **2** |
| `scripts/` | 4,913 | — | manual tools |
| `integrations/` | 0 | — | empty directory |

The workflows: static triage, dynamic runtime collection, a manual API tester,
OpenAPI/Swagger spec review, browser-extension inspection, and unified
reporting. The GUI is the front door to all of them.

---

## Is the dynamic side in a good spot?

**Broadly yes, and for a specific reason worth naming before it gets lost.**
The dynamic side is not mature because it has a lot of detectors. It is mature
because of a discipline that shows up in every one of them:

- **Every detector says whether its input was collected.** `collection_available`
  in the registry-read pass, `available` in module integrity, the *Not Compared*
  renders in the report. A zero from a run that collected nothing never reads
  as a clean result.
- **Every filter counts what it removed.** Background reads, other-process
  crashes, images set aside as resource-only, opens by processes outside the
  tree. A signal that fires on everything says nothing, and the only way to know
  which you have is to keep the number you discarded.
- **Tests aim at the failure mode.** The uncollected render must differ from the
  clean render. The whole page is rendered, not just the fragment, because a
  section function never called is indistinguishable from one returning `""`.
- **The lineage contract is honoured everywhere.** `None` means count
  everything, an empty set means attribute nothing. Audited across all five
  passes on 13 Aug; no pass conflates them.

That discipline exists because the project paid for it repeatedly — the
dead-marker bug that discarded every file write for the life of the project, the
analyzer-attribution filter, the carver and the identity gate both skipping the
same object, and most recently a cache eviction that silently dropped
`header_mismatch` for any process with more than 96 modules.

### What is genuinely left on the dynamic side

Nothing that blocks moving on. In rough order of value:

1. **The detectors have never been measured on a live run.** The ntdll-unhooking
   pass, the WER timestamp check and module integrity are all built, tested and
   *unscored on purpose*, because their false-positive rates are unknown. One
   detonation with the current build turns three "probably useful" detectors
   into three measured ones. **This is the highest-value dynamic work left, and
   it is a run rather than a code change.**
2. **`procmon.exe` is on the sample's blocklist and the guest runs Procmon.**
   Measured, not suspected: serving a hit diverts the sample 233M blocks earlier.
   Decide about renaming before the next detonation, not after reading a quiet
   report.
3. **Gap 4's active half** — "read a VM artifact, then went quiet" — is still
   only a collection path. It wants a live run before a detector is built on it.
4. **Scoring is untouched by the last three detectors.** They feed the report,
   not the verdict. That is correct until (1) happens, and then it is a decision.

### What I would not claim

The dynamic side has never been run end to end against a *benign* corpus of any
size. Both controls pass and the UPX control under-predicts by design, but
"false positive rate across ordinary software" is not a number this project has.
That is the honest gap behind every "not scored" note.

---

## The thing that actually matters before static

**`static_triage_engine/` is 6,419 lines with two tests, and `pytest` does not
run them.** `pytest.ini` sets `testpaths = dynamic_analysis/tests`, so
`static_triage_engine/tests/test_scoring.py` is only reached by naming it
explicitly. Both tests cover one function — the installer-context flag in
`score_static`.

Compare what is in there: `engine.py` (1,291 lines), `report.py` (1,160),
`scoring.py` (1,150), `api_spec_analysis.py` (928). Scoring and reporting logic
that produces verdicts an analyst acts on.

**This is where the next "count that never moved" is hiding, and nothing would
tell you.** Every class of bug this project has found on the dynamic side —
markers that match nothing, a filter that excludes the interesting object, a
detector whose input was never collected, a count derived from a truncated list
— is equally possible in static triage, and there is no test that would fail.

That is not an argument for stopping. It is an argument for the *first* piece of
static work being a harness rather than a feature.

---

## Roadmap

### Phase 1 — make static legible before extending it

1. **Put `static_triage_engine/tests` on `testpaths`.** One line. Until then
   every test written there is invisible to the default run.
2. **Characterisation tests for `score_static`.** Not aspirational tests —
   pin what it *currently* does on a handful of real cases, so refactoring is
   possible at all. This is the enabling step for everything below.
3. **Apply the `collection_available` pattern.** For each static step — capa,
   FLOSS, YARA, VirusTotal, LIEF — the summary should distinguish *the tool ran
   and found nothing* from *the tool was absent, failed, or was skipped*. On the
   dynamic side that distinction has caught real bugs four times. `tools/capa`,
   `tools/floss` and `tools/yara` are external and can silently be missing.
4. **Audit the static scoring for the same bug class**: counts derived from
   truncated lists, markers matched with the wrong separator convention,
   filters that drop the object of interest. The dynamic audit notes in
   `docs/HANDOFF.md` are the checklist.

### Phase 2 — the API workflows

There are two distinct things both called "API", and they should be kept apart:

- **Manual API tester** (`gui/api_window.py`, `static_triage_engine/api_analysis.py`,
  241 lines) — an analyst-driven request/response tool with evidence capture.
- **OpenAPI spec analysis** (`api_spec_analysis.py`, 928 lines,
  `gui/spec_window.py`, fixture at `test_specs/petstore3_openapi.json`) — static
  review of a specification.

The spec analyser is the one with real logic and zero tests, and it already has
a fixture sitting next to it. That fixture plus characterisation tests is the
cheapest way to make it safe to extend. The README's "additional API Spec
Analysis depth and rule tuning" is exactly the kind of work that wants tests
first, because rule tuning without a regression suite is how a rule set quietly
stops matching.

### Phase 3 — the surfaces

- **`gui/` has 13,667 lines and no tests.** Not necessarily wrong for a GUI, but
  the controllers under `gui/controllers/` hold logic that is testable and
  currently is not.
- **`integrations/` is an empty directory** with only a `__pycache__`. Either it
  is vestigial and should go, or something was planned there. Worth deciding
  rather than leaving.
- **Unified reporting** (`gui/unified_report_window.py`, 1,442 lines) is where
  static and dynamic meet. It is the natural place for a cross-workflow verdict,
  and the natural place for two scoring models to disagree in a way nobody
  notices.

---

## If you do one thing next

**Detonate the current build.** Three detectors are finished and unmeasured, the
guest is a commit behind, and every one of them was written to be judged by what
it fires on rather than by argument. It is also the only item here that cannot
be done later at the same cost — the sample, the guest and the questions are all
loaded right now.

**If you would rather move to static, do Phase 1 items 1 and 2 first.** They are
small, and they are what makes everything after them reversible.
