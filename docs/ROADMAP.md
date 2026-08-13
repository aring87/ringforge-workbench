# Finishing dynamic analysis

Written 13 Aug 2026. Scope is `dynamic_analysis/` — the pipeline. The emulator
in `scripts/` belongs to the `422e30ed` investigation, not to this, and mixing
the two is why "how much is left" keeps feeling unanswerable.

---

## What "done" means here

Not "every feature built". The build queue is nearly empty already. Done is:

> **Every detector has fired at least once on real data, or is explicitly
> recorded as never having fired and why.** Nothing scores that has not been
> measured. Nothing silently reads as clean when it was never collected.

That is the project's own standard, applied to itself. The proven/unproven
ledger in `docs/HANDOFF.md` is the checklist; this is the plan for emptying it.

**The shape of the remaining work is validation, not construction.** One
detector is unbuilt. Fourteen things are built and unproven. That ratio is the
whole roadmap.

---

## The build queue — one item

**Gap 4's active detector: "read a VM artifact, then went quiet."** The
collection path underneath it is *proven end to end* (07 Aug 14:53, 143,805
registry reads captured, lineage resolved, hits produced, and its first contact
with real data found the Windows-background false-positive class it needed to).
What does not exist is the thing that reads a VM check followed by silence and
says so.

It is deliberately last. It needs a live run to show what it fires on, and
building it before that is the mistake this project has corrected repeatedly.

---

## The proof queue

Grouped by what unblocks each, because that determines the order.

### A. Unblocked by one detonation of the current build

| Thing | Status today |
|---|---|
| WER image-timestamp check | Built 13 Aug, never run live |
| ntdll-unhooking pass | Built 13 Aug, never run live |
| Module-integrity report section | Rendered 13 Aug, never run live |
| Module integrity `replaced` verdict | Never seen in the wild |
| Dropped-file lineage | Fixed, unproven |
| Carve on long paths | Fixed, unproven |
| Crash-dump `hollowing_target` | Fixed, unproven |
| `procmon_filter` in the summary | Built, unproven |
| Windows-response suppression | Proven by replay, unproven on a fresh run |

Nine items, one run. This is by far the best return available.

### B. Needs a different sample or scenario — **mostly already done, 13 Aug**

**I overstated this queue and the correction matters, because it shrinks what
is left.** The ledger's "unproven" means *live-unexercised*, not *untested*, and
I read it as the second. Checked one by one:

| Thing | Actual state |
|---|---|
| Multi-region carve | **Already unit-proven.** `test_an_image_split_across_regions_is_reassembled` builds a payload cut across two adjacent ranges and asserts the carve produces all 0x4000 bytes, plus a gap case that refuses to bridge. My "drive it with a fixture" was work that already existed |
| Received-file collection | **Already unit-proven**, 10 tests including a new upload being collected and FakeNet's own shipped files not being reported as uploads |
| Adaptive window | **Already unit-proven**, 11 tests covering the cap, the silent-at-cap record, and a probe that throws |
| Split-API YARA rule | **Was the real gap, now closed.** See below |
| Sysmon Event 25 | Enabled and silent by measurement. Nothing to build |

So queue B reduces to one item that genuinely needed work, and it is done.

**The split-API rule had only ever been proven not to *misfire*.** Zero matches
across 13 live dumps and 120 genuine .NET assemblies says nothing about whether
it detects, and its subject had never been in memory on a run that scanned. That
is answerable offline: stage 2 is on the artifact drive.

    negative control, 3 unrelated processes  -> no match
    the same 3 dumps with stage 2 resident   -> 3 of 3 matched

with each split fragment asserted individually, so a change in the loader's
splitting names the fragment that went. `test_split_api_rule.py`, marked `slow`.

*A trap recorded there because it looked like a false positive and was not:* the
first control was a dump of the scanning process, and it matched before the
payload was added. Stage 2 has to be unwrapped into the scanner's heap to be
scanned, and the compiled rules hold `"kernel "` and `"Virtual "` as literals —
**a scanner scanning itself always matches**.

Everything remaining here is *unit-proven, live-unexercised*, which is a
legitimate end state under exit criterion 1 and does not block "done".

### C. Needs a corpus, not a sample — **harness built, first numbers in, 13 Aug**

**No false-positive rate for ordinary software** was the single largest gap
between "works on three samples" and "trustworthy pipeline". It turns out not to
need the VM at all: the carver and module integrity consume minidumps, and this
host has a couple of hundred ordinary processes.

`scripts/benign_baseline.py` dumps them and runs the same passes. First result,
8 processes and **152 modules compared**:

| metric | benign |
|---|---|
| unmapped PE images | **0** |
| unmapped in a hollowing target | **0** ← the emphatic branch, with an `svchost.exe` in the sample |
| `replaced` / `header_mismatch` | **0 / 0** |
| `resource_only` set aside | 7 — the known MUI class, handled not reported |

**Treat that as encouraging, not as the number.** Sorting by smallest process
put six copies of `conhost.exe` in the sample, so "0 across 8 processes" was
really 0 across *three programs*. Selection now takes one process per distinct
executable before any repeat — 14 distinct binaries are reachable here — and the
wider run has not been taken yet.

Two selection bugs found by running it, both recorded in the source because both
produce a plausible-looking wrong answer: selecting on **working set** picked
processes whose resident sets are small and whose reserved address spaces are
not, producing 445 MB and 796 MB dumps (`vms` predicts dump size, `rss` does
not); and taking the N smallest destroys binary diversity, which is the only
thing a false-positive rate is actually about.

**Still owed here:** the 14-binary run, and the same treatment for the two
detectors this cannot reach — the WER timestamp check and the ntdll pass both
need an event log and a Procmon capture, so their benign rate comes from Run 2
rather than from this harness.

---

## The plan

### Run 1 — the loader, current build

The one that clears queue A. Pre-flight, because three of these have bitten
before:

1. **`git pull` on the guest.** It is many commits behind; every 13 Aug detector
   is host-side only until it does.
2. **Point the Procmon config at `dynamic_registry_reads.pmc`.** A run on the
   default config cannot see registry reads, and a previous run was set up for
   exactly this and tested none of it because the field was left on the default.
3. **Decide about `procmon.exe` before launching, not after.** It is on this
   sample's blocklist — measured, not suspected: serving a hit diverts it 233M
   blocks earlier and it never creates its mutex. If the chain ever gets past
   the crash, Procmon's presence aborts the payload.
4. **Write the expected results down first.** That is what made gap 1 findable.

Then read, in this order: `crash_summary.image_timestamps`,
`memory\module_integrity.json`, `procmon\ntdll_unhooking.json`.

**Pre-registered prediction**, so the run can disagree: the WER timestamp check
fires (Windows recorded `5ff2b99b` for a `RegSvcs.exe` whose file is
`68531ee1`), module integrity reports `header_mismatch` on `regsvcs.exe @
0x400000`, and the ntdll pass shows the sample opening `ntdll.dll` — because the
emulator watched it do exactly that at `0x202f457`. If the ntdll pass shows
*nothing*, the interesting question is whether the read happens before Procmon
attaches.

### Run 2 — the same build, benign

A handful of ordinary installers and signed applications through the same
pipeline. Purpose is queue C: what do these detectors say about software that is
not malware. Cheap, and it is the number that decides whether any of the three
new detectors may score.

### Then — decide scoring

With A and C measured, each new detector gets one of three outcomes, recorded
either way:

- scores, with a band and a reason
- stays context-only, with the false-positive rate that made that the right call
- is removed

Right now all three are context-only *by default* rather than by decision, which
is the correct temporary state and a bad permanent one.

### Then — build gap 4's detector

Last, with the data to aim it.

---

## Exit criteria

Dynamic is finished when all five hold:

1. The proven/unproven ledger has no row reading "built, unproven" without a
   named reason it cannot be exercised.
2. Every detector that fires on the loader has a recorded false-positive count
   from the benign corpus.
3. Every detector is either scored or explicitly context-only *by decision*.
4. Gap 4's active detector exists, or is recorded as declined with a reason.
5. `pytest` is green including `slow`, and the `slow` fixture staleness guard
   has survived at least one Windows Update. *(It was added 13 Aug after a
   patched host silently rotted the reference dump for two days.)*

None of that requires new features. It requires runs, and writing down what they
showed.

---

## After dynamic

Not now — but so it is not lost. `static_triage_engine/` is 6,419 lines with two
tests, and until 13 Aug `pytest` did not collect them at all. `gui/` is 13,667
lines with none. The first static task is a harness, not a feature: pin what
`score_static` currently does, then apply the `collection_available` pattern to
capa / FLOSS / YARA / VirusTotal, all of which can be silently absent.
