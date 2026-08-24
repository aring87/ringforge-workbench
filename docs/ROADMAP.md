# Finishing dynamic analysis, and what came after

Written 13 Aug 2026, extended 24 Aug. The original scope was
`dynamic_analysis/` — the pipeline. The emulator in `scripts/` belongs to the
`422e30ed` investigation, not to this, and mixing the two is why "how much is
left" keeps feeling unanswerable.

**That scope is now largely closed, and the work moved.** For the current plan,
start at *After dynamic — the roadmap from 24 Aug* at the end of this file. The
sections between are the dynamic plan and its outcomes, kept because the
standard below is quoted by `docs/SCORING.md` and because how each item closed
is more useful than the fact that it did.

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

### A. Unblocked by one detonation — **run `d7cc5044` happened, 13 Aug**

| Thing | Outcome |
|---|---|
| WER image-timestamp check | **Proven on real malware.** Prediction exact, and it fired on a run where no usable dump existed at all |
| ntdll-unhooking pass | **Proven.** `RegSvcs.exe` opened `ntdll` twice; two contamination bugs found and fixed, baseline now 2 |
| Module-integrity report section | **Rendered live** |
| `header_mismatch` on the payload | **Proven** — from the WER crash dump, offline, after the run |
| Module integrity `replaced` verdict | Still never seen in the wild |
| Windows-response suppression | **Proven on a fresh run**, by being the fix this one needed |
| Registry-read finding path | **Still unexercised** — wrong Procmon config, third attempt |
| Dropped-file lineage / long-path carve / crash-dump `hollowing_target` | Untouched: this run dropped no files and carved nothing from a long path |

The run cost one detonation and settled five rows, exposed four attribution
bugs, and left one item needing only a checkbox next time.

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

`scripts/benign_baseline.py` dumps them and runs the same passes. **Measured
13 Aug: 12 distinct programs, 491 MB of dumps, 300 modules compared.**

| metric | benign |
|---|---|
| modules compared | **300, all `identical`** |
| unmapped PE images | **0** |
| unmapped in a hollowing target | **0** — with an `svchost.exe` in the corpus |
| `replaced` / `header_mismatch` | **0 / 0** |
| `resource_only` set aside | 5 — the known MUI class, handled not reported |
| `no_reference` | 2, both in a Canon printer utility, counted not skipped |

The corpus is a browser, a browser host process, a music client, a shell, a
printer utility, a toast-notification host, a Windows background task host, a
crash handler, Python, and `svchost.exe` — which matters because it is in
`HOLLOWING_TARGETS`, so the **emphatic branch was exercised and did not fire**.
Two processes refused `OpenProcess` (a game anti-cheat and an NVIDIA helper) and
are counted as `dump_failures` rather than passed over.

**Set against the malware, the discrimination is clean.** The same two passes on
run `d7cc5044`'s crash dump reported `header_mismatch` on `regsvcs.exe @
0x400000` at 99.10% differing, plus two unmapped `ntdll` copies in private
memory. Benign: nothing, 300 times.

**State it as what it is.** This is *0 in 300 module comparisons across 12
programs on one machine at one moment* — not a percentage with a confidence
interval. It is enough to say the dump-based passes do not fire on ordinary
desktop software, and not enough to characterise a rate.

**The gate fix is verified on the guest — 21 Aug.** The benign `Add-Type`
compile that produced `unmapped 4, both in a hollowing target` on 20 Aug now
produces **`unmapped 0, framework_assembly 4`** at the same 36-module depth
(118.8 MB dump against 116.0 MB). The four were identified and suppressed rather
than absent — `framework_assembly 4` is the positive control, and `0, 0` would
have meant the compile never loaded them. Module integrity clean alongside: 36
identical, 0 patched, 0 replaced, 0 `header_mismatch`.

**Two caveats stay on the record.** The benign rate behind `strong` on any
unmapped image is **16 processes on one host**, not the 870 module comparisons
it was cited as — that number belongs to the module-integrity pass. And
`_FRAMEWORK_PREFIXES` accepts `system.*`/`microsoft.*`, so a payload naming
itself `System.Foo.dll` is suppressed by name.

**Managed processes measured 20 Aug — 570 comparisons, still 0.** The 13 Aug
corpus contained no .NET process at all, which mattered once run `c14cb5b6`
graded **strong** on five .NET images inside a legitimately spawned `csc.exe`.
`--pid` was added to reach processes the size-ranked corpus will not pick.

| metric | benign .NET |
|---|---|
| applications | 4 — Aura, ArmouryCrate ×2, CrossDeviceService |
| modules compared | **570, all `identical`** |
| unmapped PE images | **0** |
| `replaced` / `header_mismatch` | **0 / 0** |
| `no_reference` | 8, counted not skipped |
| oversize skipped | 2 — Overwolf 985 MB, PhoneExperienceHost 699 MB |

**So the CLR does not inherently produce unmapped images**, and "exclude .NET"
was never the right shape of fix. The remaining suspect is *compilation* —
assemblies loaded dynamically rather than mapped — which is narrower and would
leave `422e30ed` detectable. See the decisions section of `HANDOFF.md`.

**A benign `csc.exe` cannot be dumped on this host.** `MiniDumpWriteDump`
returns `0x80070005` on a compiler spawned by our own PowerShell, while sixteen
other processes dump fine; Bitdefender is the near-certain cause. The identical
code dumps it in the guest, so **any measurement involving a spawned child
belongs there**.

**Run in the guest, 20 Aug — the gate does not fire on a benign compile.**
`csc.exe` dumped three times during a real `Add-Type`, keeping the last at
+1.75 s, 48.2 MB, **33 modules** — against 36 in the malware run's dump of the
same binary, so loaded compiler against loaded compiler.

| | modules | unmapped |
|---|---|---|
| benign `csc.exe` | 33 | **0** |
| `c14cb5b6` `csc.exe` | 36 | **4** |

**But the five images were then read, and decision 1's premise stands.**
`dotnet_meta.py` identifies them as `mscorlib` (3356 typedefs, 29257 methods)
and `System.Management.Automation` (3692 typedefs, 33669 methods) among others
— framework assemblies, not payloads. So the gate did grade **strong** on the
CLR's own code.

**And a benign compile then reproduced it.** `--only-managed --no-refs`, 2,500
trivial classes, nothing malicious: **`unmapped 2`, both in a hollowing target**.

| run | refs | dump MB | modules | unmapped |
|---|---|---|---|---|
| guest 1st | no | 31.2 | 9 | 0 |
| guest2 | no | 48.2 | 33 | 0 |
| refs | **yes** | 39.8 | 33 | 0 |
| **norefs** | no | 62.6 | 35 | **2** |
| **norefs2** | no | **116.0** | **36** | **4** |
| `c14cb5b6` | — | — | **36** | **4** |

**Benign and malicious are indistinguishable** — same module count, same
unmapped count, and the four benign images byte-identical in size to the
sample's. The variable is dump completeness, monotonic in module count every
time; references and the sample itself are irrelevant.

**Reproducing needs the compile to reach ~36 modules.** A freshly reverted
guest compiles 2,500 classes too fast — a single dump at 9 modules.
`--probe-classes 12000` reaches it. Below the mid-30s the test has not run, so
check the module count before reading a 0.

**No attribution bug.** `host_image` reads `csc.exe` on the benign dumps. The
PowerShell engine appears inside a C# compiler because `csc.exe` memory-maps
its reference assemblies to read metadata, and `Add-Type` passes the calling
session's loaded assemblies — which is also why the `-ReferencedAssemblies` arm
changed nothing.

**The fix**: exclude images whose metadata identifies them as known framework
assemblies. Both sets are the same four framework assemblies, so metadata
discriminates where an address heuristic would not, and `422e30ed` stays
detectable because its payload is a custom assembly in `RegSvcs`.

**And an unresolved anomaly:** `System.Management.Automation` cannot be in
`csc.exe`. Either an image is attributed to the wrong dump or a dump is named
for the wrong process — and if `powershell.exe` images are landing under a
`csc.exe` label, `hollowing_target` is computed from the wrong name. The source
dumps died with the revert, so confirming it needs a fresh run that keeps them.

**Dumping a just-spawned process fails benignly.** `csc.exe` and `cvtres.exe`
both returned `0x8007012B` `ERROR_PARTIAL_COPY` on first attempt and dumped
fine moments later, with no malware present. **That error alone is not evidence
of an image being rewritten** — which is what decision 2 currently rests on.

**Still owed here:** the same treatment for the two detectors this harness
cannot reach. The WER timestamp check needs an event log and the ntdll pass
needs a Procmon capture, so their benign rates come from a benign *detonation*
— Run 2 — not from dumping local processes. Note the ntdll pass already has a
partial answer from the malware run: 2 background opens after the analyzer and
WerFault were excluded, against 3 by the sample's own tree.

---

## The plan

### Run 1 — the loader, current build — **RAN 13 Aug as `bb51babb`, all rows passed**

Queue A is clear and the registry-read question is answered: the sample makes
73,825 registry reads and **none name a VM artifact**, verified against a
positive control in the same stream. Gap 4b's finding path and gap 4's
threshold both need a *different* sample now — re-running this one produces the
same zero. The pre-flight below is kept because it applies to any future
detonation, not because this run is still owed. See *Run `bb51babb`* in
`docs/HANDOFF.md`.

The one that clears queue A. Pre-flight, because three of these have bitten
before:

1. **`git pull` on the guest.** It is many commits behind; every 13 Aug detector
   is host-side only until it does.
2. **Confirm the Procmon config reads `dynamic_registry_reads.pmc`.** It is now
   the default and the launch pre-flight warns if the chosen config captures no
   registry reads, so this should take a glance — but a saved
   `dynamic_procmon_config_path` in `config.json` still wins over the default.
   Three runs were set up for exactly this and tested none of it because the
   field was left alone.
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

**Built 13 Aug, and the data to aim it did not arrive — by measurement, not by
omission.** Two samples that provably detect virtualisation both produced
`artifacts_read: 0`: FormBook checks by module hash, and `a6a86646…` — chosen
*because* a sandbox flagged it as reading VirtualBox ACPI keys — announced
*"cannot run inside a virtual machine"* on screen while touching no registry VM
key, no VM-named file, no device namespace and no WMI. The registry is one
narrow surface of VM detection and the field does not favour it, so the
threshold's input is rarer than this plan assumed. **Take the second outcome
above: context-only, with the reason recorded.** Aiming it later needs a sample
confirmed by reading its code, not by a sandbox signature.

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

## After dynamic — the roadmap from 24 Aug

The 13 Aug note below this heading read, in full:

> `static_triage_engine/` is 6,419 lines with two tests, and until 13 Aug
> `pytest` did not collect them at all. `gui/` is 13,667 lines with none. The
> first static task is a harness, not a feature: pin what `score_static`
> currently does, then apply the `collection_available` pattern to capa / FLOSS
> / YARA / VirusTotal, all of which can be silently absent.

It was right about the shape and wrong about one thing: `score_static` was not
worth pinning. Pinning it would have preserved three false positives. See
*Phase 2* below.

### Why this happened at all

The repo held **two independent scoring systems** that did not share a scale or
a vocabulary:

- `static_triage_engine/scoring.py` — additive points, static capped at 40,
  dynamic at 30, summed and clamped to 100, banded with thresholds derived for
  the 0–40 scale. `MALICIOUS` fired at 30 of 100, while the VirusTotal branches
  in the same function tested 50 and 75.
- `dynamic_analysis/orchestrator.py` — category agreement. *Three agreeing
  categories, or two strong ones, is Likely Malicious.*

The combined score re-scored the dynamic module's corroboration output back into
additive points on the way in, and the unified report displayed both
vocabularies at once with no stated relationship between them. `docs/SCORING.md`
is the design note; this is the schedule.

### Done — 24 Aug

**Phase 0 — the contract** (`168302c`). `verdict/` holds the `Category` shape,
the band function and the invariants, consumed by nothing. 28 tests.

**Phase 1 — dynamic on the shared model** (`49f628c`).
`test_score_discrimination.py` passed **unchanged**, which is the record that
the bands survived the move rather than being renegotiated during it. The lift
forced the coverage question the dynamic side had never had to answer, and
answering it found a live bug: a run with memory YARA disabled reported
*Benign / Clean Baseline*.

**Phase 2 — static authors categories** (`c5b26e3`). Six categories, everything
injected, no case-directory reads. Static went from 2 tests against 6,518 lines
to 36 — and writing them found three false positives in the additive scorer,
each of which the 13 Aug plan would have preserved by pinning:

1. A hash-like filename charged 6 points, and this pipeline acquires samples by
   hash and stores them under it. Every sample it ever downloaded started six
   points up.
2. An empty version-info block would have stood alone at Elevated Attention,
   sweeping up Go and Rust binaries and anything built without a resource
   script.
3. Being unsigned was worth 8 points. Absence of exculpatory evidence is not
   incriminating evidence.

Each time the additive model priced something it could not justify, and the
price hid that it could not.

### Phase 3a — spec — **DONE, 24 Aug**

Four categories, 21 tests against a scorer that had none. It found three more
defects of the same shape as Phase 2's, and the full account is in
`docs/SCORING.md`; the headline is that **an unparseable spec scored 10 of 30
for having no authentication**, because the test was `auth_scheme_count == 0`
and an empty dict satisfies it.

The prediction in the line below this heading — *this one has no tests at all,
so read it with Phase 2's question* — was worth writing down, because it paid
out three times.

### Phase 3b — api and extension have no engine layer

**This is not the rename the design note assumed.** `gui/extension_window.py` is
1,743 lines and performs the analysis *itself* — zip/crx extraction, manifest
parsing, file inventory, risk verdict — inside a Tkinter `Toplevel` that imports
nothing but the theme. `gui/api_window.py` is 1,394 lines and is built the same
way.

Neither can emit categories until the logic is extracted from the window, and
that is also why neither has a single test: there is nothing importable to test.
Until then they report `collected: false` and contribute nothing, which is at
least true.

### Phase 4a — the combiner

Where the current incoherence actually hurts. Seven things break, and they are
listed in `docs/SCORING.md` under *What breaks* rather than repeated here. The
headline: `calculate_combined_score`, `classify_verdict` and `score_dynamic` are
**deleted**, not migrated — the last of those removes an entire re-scoring path.
`combined_score.json` changes shape, 19 files reference the retired verdict
strings, and a test should pin that none of them survives.

### Phase 4b — the report and the theme

The flow work. One verdict to display makes the unified report a design problem
instead of a reconciliation problem.

The theme is bounded and measured: `gui/theme.py` defines 40 colours,
`dynamic_analysis/report_theme.py` defines 17, and they share **zero** values —
which is why the application and its own reports read as different products. On
top of that, 37 hardcoded hex colours bypass the theme entirely:
`extension_window` 14, `unified_report_window` 9, `dynamic_window` 8,
`api_window` 6. One source, both media derived from it, and a test asserting no
literal hex outside it.

### The order, and why

**3a → 4a → 4b → 3b.**

Spec is cheap and keeps the contract honest while it is still young. The
combiner is where two verdict vocabularies in one window stop being a design
note and start being a fix. The report and theme are the payoff. The
api/extension extraction is real work with no verdict consequence until it is
finished, so it goes last — unless those two modules need to be trustworthy
sooner, in which case it moves up and nothing else changes.

### The dynamic track, still open and independent

1. **The contract's transaction history.** Blocked on a BscScan key or an
   archive node; the public node prunes historical state and refuses wide
   `eth_getLogs`. No detonation. The script does not exist yet — the "drafted"
   code referred to in `docs/HANDOFF.md` is not in the repo.
2. **Why `bait6` produced the hardcoded wallet.** Needs bench time, one
   detonation per revert. Arm A — an unusable C2 response served to a fresh
   payload — is cheaper and tests the likelier explanation, so it goes first.
3. **The FakeNet shim for `beacon_responder.py`.** Built, never wired, not
   needed for anything currently open.

**And the baseline re-take is mid-flight.** Verified through the pre-freeze
checklist with `timeout 240` corrected to `900`; the take, restore-verify,
delete and rename were not confirmed. Close that before anything else touches
the VM — a half-replaced baseline is the one state nothing in this bench is safe
on top of.
