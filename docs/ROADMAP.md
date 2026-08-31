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

## The build queue — empty

**Gap 4's active detector was built, and this heading was stale.** Checked on
28 Aug: `correlate_vm_check_with_silence` in
`dynamic_analysis/vm_artifact_reads.py` answers four ways --
`not_collected`, `no_vm_check`, `checked_then_active`, `checked_then_quiet` --
is wired into `orchestrator.run`, renders as a `card-alert` in the HTML report,
and carries 14 passing tests. The section below described it as the one thing
that did not exist.

**What is missing is calibration, not code.** `QUIET_EVENT_THRESHOLD = 10` is
labelled a placeholder in its own comment: *the right value is whatever a live
run shows separates a bail from a pause, and no live run has shown it.* The
detector has never fired because no run has yet produced a `vm_specific`
registry read -- only `identity_surface` ones, which it deliberately refuses to
count, because `SystemBiosVersion` is where a VM check looks *and* where an
inventory agent looks.

So it needs a sample that actually checks for a hypervisor, detonated with the
registry filter that captures reads. That is a detonation, not a build.

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

## Pick up here — 28 Aug

### Start here — the whole of 28 Aug in one screen

**One correction ran through everything below.** `stripped_metadata` was
published at 100% on malware and was measuring the signature check: no collector
ever wrote the version-info block it reads, so it had silently become a second
copy of `invalid_signature`. Fixing the collector exposed 56 malware samples
that nothing could see, and the rest of the day was spent characterising them
and building against what they actually were.

    category                      Sys32   ProgFiles     family      6-year
    ─────────────────────────    ──────   ─────────   ─────────   ─────────
    stripped_metadata              0.0%        6.0%       77.2%       60.0%
    high_entropy_sections          0.3%        0.0%       35.4%       28.0%
    dangerous_capability           0.7%        2.4%       25.0%       15.4%
    known_malware_signature        0.7%        0.3%       16.5%       12.0%
    invalid_signature              0.0%        0.0%       15.7%        6.0%
    deceptive_file_identity        0.0%        0.0%        8.7%        7.0%
    obfuscated_managed_code        0.0%        0.0%        4.7%        4.0%
    embedded_network_indicators    8.6%       77.0%       71.7%       67.0%

    bands, No Evidence            98.3%       91.7%        1.6%       17.0%

Three categories shipped, each measured before it shipped. `dangerous_capability`
re-fitted from 3/5 to 4/6 once benign .NET applications entered the corpus.
**No Evidence on malware went 56 to 19.**

**One item is open. Gap 4 closed on 31 Aug, by measurement.**

1. **True positives for `extension`, `spec`, `api`.** OWASP crAPI and VAmPI are
   downloadable; delisted malicious extensions are not.

**Gap 4's detector is declined with a reason, and exit criterion 4 is
satisfied.** Two detonations of `ce0d08be...` -- the only 1 of 226 malware
samples naming a VM-only registry key in its own bytes -- watched the installer
stage and then, across an `ONLOGON` task, the payload stage. The payload ran
resident and elevated for an hour and made **967 registry reads, none of them a
VM artifact**, on a capture that demonstrably saw it. Against that, Windows
itself makes ~450 `vm_specific` reads per ordinary boot. The surface is rare in
the field and swamped by the OS where it appears. See *Item 1 - the logon run*;
the collection path is proven, and the one untested gate -- a completed C2
handshake -- cannot be tested with this sample, whose C2 is hardcoded
`127.0.0.1`.

**Answered — do not reopen without new data.** Each of these was measured and
the answer written next to the code:

    entropy to `strong`?          no -- 0.95% of installers fire, 0.00% installed
    lower the entropy cut to 7.2? no -- installer rate doubles; band unchanged
    signature-subject matching?   no -- 15% FP; bundled software is signed by
                                  its distributor
    rarity of .NET API refs?      no -- 60% of benign refs appear in one assembly
    capa namespaces within .NET?  no -- a library-vs-application confound
    add the candidate namespaces? no -- lift falls 4.7x to 3.2x
    narrow `embedded_network_…`?  no -- 2.7x on clean data, bar is 4.2x
    add Windows Defender?         cannot -- real Defender binaries say
                                  `Microsoft Corporation`

**19 samples resist every category**, and `CALC.EXE` is their shape: 56
VirusTotal detections, a signature that verifies, zero capa rules, zero YARA.
No static category reaches it. That is the argument for the dynamic side, not
for a ninth category.

**The habit that paid, six times.** Read the existing state before writing
anything. capa was already running on .NET; the version-info field was read but
never written; `benign_rates` silently measured System32 under a `--cases` it
could not honour; capa was on the host PATH after I reported it absent; Gap 4's
detector was already built; Windows Defender was never behind a missing root.
Every one of those looked like work to do and was a thing to check.

**Where the data is.** `G:\static-corpus-full\cases` (292 System32),
`G:\pf-corpus\cases` (300 Program Files), `G:\benign-managed-cases\cases` (124
managed applications), `G:\benign-survey.json` + `G:\benign-survey-vm.json`
(1,593 binaries for threshold calibration), `G:\installer-survey*.json` (210
installers). Malware is on the guest at `C:\mal-bazaar-cases\cases` and
`C:\mal-datalake-cases\cases`; the host copies carry analysis output only and
report `unknown` for anything needing the binary.

**Everything below this line is the working detail**, in the order it was found.

**`stripped_metadata` was never measuring metadata.** No collector ever wrote a
version-info block, so `_pe_string_table` returned `{}` on all 819 samples and
the category collapsed into `not trusted_signed` — a relabelling of the
signature check, which is already its own category. The collector now extracts
the block and **all four corpora are re-measured**. The 27 Aug section this
replaces is preserved in the git history.

    category                      Sys32   ProgFiles     family      6-year
    ─────────────────────────    ──────   ─────────   ─────────   ─────────
    stripped_metadata  §           0.0%        6.0%       77.2%       60.0%
    dangerous_capability ★         0.7%        2.4%       25.0%       15.4%
    invalid_signature              0.0%        0.0%       15.7%        6.0%
    known_malware_signature        0.7%        0.3%       16.5%       12.0%
    embedded_network_indicators †  8.6%       77.0%       71.7%       67.0%
    deceptive_file_identity ‡      0.0%        0.0%        8.7%        7.0%
    high_entropy_sections ¶        0.3%        0.0%       35.4%       28.0%
    obfuscated_managed_code ‖      0.0%        0.0%        4.7%        4.0%

    bands, No Evidence            98.3%       91.7%        1.6%       17.0%
    at 13 vendors, before Oracle  98.3%       91.7%        1.6%       16.0%
    at the old 3/5 thresholds     97.9%       90.3%        1.6%       15.0%
    before obfuscated_managed     97.9%       90.3%        3.9%       17.0%
    before entropy and identity   98.3%       90.3%       19.7%       31.0%
    before the collector fix      98.3%       86.0%        0.0%        3.0%

    § re-measured 28 Aug with the collector fixed; was 0.0/10.3/100.0/95.0,
      every one of which was `not trusted_signed` reproduced to the decimal
    † held in `verdict.CONTEXT_ONLY_CATEGORIES` -- fires *less* on malware
    ‡ rebuilt 28 Aug on the version block. Had never fired on 819 samples in
      either direction; the three filename predicates remain correct and
      remain unreachable, because acquisition destroys the authored name
    ¶ shipped 28 Aug: entropy >= 7.5 in an *executable* section
    ‖ shipped 28 Aug: >= 20% of a managed assembly's identifiers renamed. One
      window into managed code, not a fix for it -- 8 of the band's managed
      samples have perfectly readable names and are still unseen
    ★ thresholds re-fitted 28 Aug from 3/5 to 4/6, because the benign corpus
      gained 124 .NET applications and the category fired on 17.7% of them at
      the old present threshold. Was 1.1/4.0/30.4/18.7. The trade is visible in
      the two band rows: benign No Evidence rises 0.4 and 1.4 points, malware by
      1.0 on one corpus and not at all on the other

**Read the three band rows together, because they are the actual result.**
Corrected, `stripped_metadata` discriminates better than the broken figure
claimed -- 77.2% and 60.0% against 0.0% and 6.0%. But it had been carrying
samples nothing else fires on, and removing the phantom exposed 56 of them:
**No Evidence on malware went 0.0% -> 19.7% and 3.0% -> 31.0%.**

Three categories, every one measured before it shipped, then recovered 39 of
the 56: **1.6% and 15.0%.** `high_entropy_sections` takes the packed ones,
`deceptive_file_identity` the ones claiming a vendor they cannot be, and
`obfuscated_managed_code` the .NET assemblies whose identifiers were renamed.
They barely overlap -- six samples between the first two, none with the third.
Their combined cost on benign is one System32 binary moving from No Evidence to
Single Observation; Program Files bands did not move at all.

**18 samples remain, and they are the honest number.** The pre-fix baseline of
3 was a phantom -- it counted samples covered by a signal that did not exist.
Against it the module still looks worse and is in fact better, which is the
whole lesson of this section in one row: a coverage figure is only as good as
the category producing it.

### What the collector fix changed

`scripts/pe_meta.py` now walks the resource directory and writes `version_info`
alongside `version_info_collected` and `version_info_present`. The categoriser
gates on `version_info_collected`, so a `pe_metadata.json` written before this
change reports `unknown` rather than clean — the collector contract applied to
our own past output.

**The two benign corpora were backfilled on 28 Aug** — 592 `pe_metadata.json`
files gained the version-info keys, read from each sample binary, no other field
touched. Scoring them straight off disk reproduces the table above exactly
(0.0% and 6.0%, no `unknown`), which is the check that the backfill and the
live collector agree. Cases that never completed were skipped, as were any whose
binary or resource directory would not parse: those keep reporting `unknown`
rather than acquiring a `collected: True` they did not earn.

**The 227 malware cases were refreshed on the guest**, where the samples still
are, using `scripts/refresh_version_info.py` — 227 of 227, no failures, twelve
seconds rather than the two hours a full re-run costs. The predicted rate was
published before the scorer ran (77.2% for bazaar, a 57–62% band for datalake,
the band being the uncertainty from five trusted-signed samples) and both
landed: 77.2% and 60.0%. Predicting first is cheap and it is the only thing
that distinguishes a measurement from a number that arrived.

The 10.3% → 6.0% drop reverses the reading in the old item 4. The false
positives did *not* cluster in GNU/MinGW builds: Igor Pavlov (7-Zip) 6/6 and
GnuWin32 5/5 carry **complete** version info and were firing purely for being
unsigned. What survives is 18 cases of a different kind — unnamed native
libraries (`libffi`, `libfontconfig`, `libhwy`, `libLerc`, `psl`), COM interop
stubs with two of four fields (`stdole`, `adodb`, `msdatasrc`), and an Inno
Setup uninstaller. A wider open-source corpus would now be answering a question
about *those*, not about the GNU toolchain.

### Where the data is

    G:\static-corpus-full\cases     292 System32 cases, full engine
    G:\pf-corpus\cases              300 Program Files cases, 55 vendors
    C:\Users\aring\Downloads\ringforge\cases\bazaar2     127 malware cases
    C:\Users\aring\Downloads\ringforge\cases\datalake2   100 malware cases

The benign corpora keep their sample binaries. **The host copies of the malware
corpora hold analysis output only** — copied under an extension allowlist,
verified no `MZ` header — so anything needing the bytes has to run on the
guest, where both corpora and their samples live:

    C:\mal-bazaar-cases\cases      127 cases   samples C:\mal-bazaar\samples
    C:\mal-datalake-cases\cases    100 cases   samples C:\mal-datalake\samples

203 of 227 still have capa.json on the host, so capability work continues not
to need the guest. Anything reading the binary — version info, entropy,
sections — does.

### Next, in value order

**The 56 are characterised — `scripts/no_evidence.py`.** They are not a residue.
Every one carries complete version info, 55 of 56 name a company, and only 3 are
signed. **The band is malware that presents as legitimate software**, which is
coherent: it is exactly the population `stripped_metadata` is defined to
exclude, so it was never covering them on merit -- it was covering them for
being unsigned. Only 1 of 25 and 1 of 31 have a collection gap, so the band is a
property of the samples and not of the pipeline. That was worth ruling out.

    of the No Evidence band          family(25)   6-year(31)   both(56)
    ─────────────────────────       ──────────   ──────────   ────────
    exec section >= 7.5                     14            7         21
    claims a major vendor, unsigned         12            8         20
    both                                     5            1          6
    NEITHER                                  4           17         21

**Both categories shipped on 28 Aug, and the band closed as predicted.** The
prediction was published before either ran -- about 4 remaining in bazaar and
about 17 in datalake -- and the result was 5 and 17.

    of the No Evidence band          family        6-year        both
    ─────────────────────────       ────────      ────────      ──────
    was                                   25            31          56
    now                                    5            17          22

`high_entropy_sections` takes the packed ones and `deceptive_file_identity` the
ones claiming a vendor they cannot be; across both corpora they overlap on only
six samples, which is why shipping both was worth more than shipping either.
Neither is `strong`. Their combined benign cost is one System32 binary moving
from No Evidence to Single Observation, and Program Files bands did not move.

`deceptive_file_identity` had never fired on 819 samples in either direction. It
now fires on 7.1% and 8.0% of the malware corpora and 0.0% of both benign ones.

Two things learned in the building, both recorded because they changed the
design:

**The signature-subject comparison does not work, and it was the construction
this section recommended.** *Claims vendor X, signed by not-X* fires on 15.0% of
Program Files and 1.0% of System32, because bundled software is signed by its
distributor rather than its author -- curl and NVIDIA signed by Microsoft,
FFmpeg by OBS Project, `@react-native-community` by Microsoft. Measuring it
before writing it cost ten minutes. The rule that survives is the derived list,
`scripts/derive_signers.py`, at 0.0% and 1.3%.

**The vendor claim has to be *complete* or the two categories double-count.**
Four Program Files binaries honestly say `Microsoft Corporation` across two of
four fields while shipping unsigned inside someone else's installer. Firing here
as well as in `stripped_metadata` carried all four to Corroborated on the single
observation of being unsigned -- Program Files Corroborated went 1 to 5 before
this was caught. Requiring the whole block splits them cleanly: a partial
identity is `stripped_metadata`, a complete and false one is this. It costs
nothing, because all 56 target samples carried four or more fields.

**The 22 are characterised, and the answer is not a seventh category.**

    of the remaining band            bazaar(5)   datalake(17)   both(22)
    ─────────────────────────       ─────────   ────────────   ────────
    managed (.NET) binaries                 4              9         13
    five or fewer imported symbols          4             10         14
    exec entropy 7.0 to 7.5                 2              6          8
    signature verifies                      0              3          3
    a collector did not run                 0              1          1

**59% of what static cannot see is managed code**, and the reason is
structural rather than a threshold anyone can move. A .NET assembly imports
`mscoree.dll` and nothing else; its real call graph is in CLR metadata. Every
category the module has reads the import table, the section table or the
version block, and a managed binary is thin or uninformative in all three. The
`five or fewer imported symbols` row is the same 13 samples plus one native
outlier, not an independent finding.

**The .NET collector and `obfuscated_managed_code` both shipped on 28 Aug.**
`scripts/dotnet_summary.py` reads the CLR metadata, `scripts/refresh_dotnet.py`
applies it to a corpus already on disk, and both are wired into
`engine.run_case`. It is explicitly *not* another PE category -- a seventh thing
reading the import table, the section table or the version block cannot see a
population defined by having nothing in them.

**1. The eight managed samples with readable identifiers. Two framings tried,
both rejected, and the second is rejected for a reason worth keeping.**

`dotnet_summary.py` now collects the `MemberRef` table -- every external method
an assembly references -- raw and unjudged, and `dotnet_api_baseline.py`
measured how common each is across 228 benign managed assemblies. No list of
suspicious .NET APIs exists anywhere in either file, deliberately.

**Rejected: rarity of API references.** 60.2% of benign references appear in
exactly one assembly, so "uses rare APIs" fires on nearly everything. Scored as
a *proportion* -- what share of an assembly's references no other benign
assembly makes, leave-one-out so the comparison is not circular -- benign runs
at a median of 0.146 with 44% above 0.20 and one legitimate assembly at
**0.819**. `SQLitePCLRaw` references `SQLitePCL.*` and nobody else does. That is
a bundled library, not a behaviour, and malware would have to clear 0.819 to
stand out. `scripts/dotnet_api_compare.py` reproduces it.

**capa is not the gap.** Worth checking before building anything: capa runs its
`dotnet` backend on all 103 managed malware samples and every one produces
rules. It is not falling back to a native view, so `dangerous_capability` not
firing on them is a real answer rather than a silent collector failure -- the
version-info hypothesis, tested and negative.

**Rejected, and this is the one to remember: capa namespaces measured within
managed code only.** `HIGH_SIGNAL_CAPABILITIES` was fitted over pooled corpora
where benign is ~11% managed, so a namespace that discriminates inside .NET
could plausibly have been diluted. Restricting to managed samples produced
sixteen namespaces at **infinite lift** -- 10-26% of malware, 0.0% of benign --
including `collection/keylog`, `host-interaction/registry/create` and
`data-manipulation/encryption/aes`.

It is an artifact. The 51 benign managed samples carrying capa are almost
entirely *libraries and satellite resource assemblies* --
`Microsoft.Bcl.AsyncInterfaces`, `Mapster.DependencyInjection`, six `*.resources`
-- and only three are applications. The 103 malware samples are all
applications. **The comparison measures library-against-application, not
benign-against-malicious**, and a library does not take screenshots or list
processes whatever its intent. Sixteen namespaces at infinite lift is what a
confound looks like when it is flattering.

**The confound was real, and removing it changed the answer.** 124 benign
managed *applications* -- every managed assembly on the host with an entry point
and no `IMAGE_FILE_DLL` flag, 124 of 3,067 executables -- were run through the
whole engine (`G:\benign-managed-cases`, built by `scripts/stage_managed_apps.py`
and `static_corpus.py`). capa analysed all 124 with its `dotnet` backend and
none produced zero rules.

    namespace                              libraries(51)   applications(124)
    ─────────────────────────────────     ─────────────   ─────────────────
    collection/keylog                        inf  (0.0%)      5.2x  (2.4%)
    data-manipulation/encryption/aes         inf  (0.0%)     19.3x  (0.8%)
    host-interaction/gui/window/get-text     inf  (0.0%)     10.8x  (2.4%)
    namespaces at infinite lift                       16                  1

Sixteen namespaces at infinite lift became one. Everything else landed between
4x and 19x against a benign rate that is small but *not zero*, which is what a
real signal looks like and what the library comparison could not show.

**A genuine finding survives it, and it is not yet a change.** Six of the top
twenty-two are already in `HIGH_SIGNAL_CAPABILITIES`. Several are not and
discriminate anyway: `data-manipulation/encryption/aes` 19.3x,
`data-manipulation/prng` 11.0x, `host-interaction/gui/window/get-text` 10.8x,
`collection/keylog` 5.2x -- the last one notable because the set holds
`host-interaction/hardware/keyboard`, its near-twin, and not it.

**Do not extend the set from this table.** Two reasons, both of which have
burned this project already. `HIGH_SIGNAL_CAPABILITIES` was fitted over *pooled*
corpora; adding members chosen on a managed-only measurement mixes
methodologies and is tuning to .NET. And the 124 benign applications are one
machine's, heavily weighted to installers, uninstallers and updaters -- a
specific population that may itself be the next confound.

The measurable version: add the candidates, re-measure `dangerous_capability`
across **all four** corpora, and keep them only if malware detection rises
without the benign rate moving. That is the same test the original set passed,
run again rather than a different test run once.

**Two results from scoring the new corpus, and the second is a caution about a
shipped category.**

`obfuscated_managed_code` reads **0.0% on 124 managed applications**. It was
calibrated on 39 measurable assemblies that were mostly libraries; this is the
population it was actually built for, and it holds.

`dangerous_capability` reads **17.7% on the same 124**, 5 of them `strong`,
against the 1.1% and 4.0% published for System32 and Program Files. Its benign
rate was established on corpora that are overwhelmingly native and, where
managed, overwhelmingly libraries. **On .NET applications it is roughly four
times worse than the table says**, and the bands agree: 26 of 124 benign
managed applications carry evidence, against 2% of System32 and 10% of Program
Files. That is not a reason to change the category today, but the published
figure should not be read as covering managed applications, and the roadmap
table should carry the caveat.

**The candidates were tested on all five corpora and rejected --
`scripts/capability_sweep.py`.** Their managed-only lifts did not survive
contact with the rest: `collection/keylog` 5.2x becomes 2.8x, `aes` 19.3x
becomes 6.5x, `prng` 11.0x becomes 4.3x. Adding all ten makes the category
strictly worse at every threshold.

    dangerous_capability      benign   malware     lift
    shipped set, at 3           5.3%     25.2%     4.7x
    set + candidates, at 3     11.3%     36.6%     3.2x
    shipped set, at 5           1.2%     18.8%    15.4x
    set + candidates, at 5      3.7%     20.3%     5.5x

Detection rises and the benign rate rises faster. That is the test the original
set passed, run again, and the candidates fail it. **The one that looked
strongest -- `communication/tcp` at 14.9x -- is a near-duplicate of
`communication/tcp/client`, which is already a member.**

**The threshold is a different matter and the same sweep says 3 is now too
low.** With managed applications in the benign side:

    at    Sys32   ProgFiles   managed apps   benign   malware    lift
     3     1.1%        4.0%          17.7%     5.3%     25.2%    4.7x   <- present
     4     0.7%        2.4%           8.9%     2.9%     20.8%    7.2x
     5     0.7%        0.4%           4.0%     1.2%     18.8%   15.4x   <- strong

The original choice of 3 was argued as *the sensitivity cost from two is small
and it more than halves the false-positive rate*. Applied to this corpus the
same sentence selects 4, and 5 no longer reaches the rate at which a category
may stand alone.

**Changed on 28 Aug to 4 and 6**, and every published rate re-measured with it.
`dangerous_capability` moves from 1.1/4.0/30.4/18.7 to **0.7/2.4/25.0/15.4**,
and on managed applications from 17.7% to 8.9%. The cost is 4.4 points of
detection; the decision rule is the one the original fit used, applied to a
corpus that now contains the population it was worst on.

**Re-measured on the guest: 1.6% and 16.0%.** A stricter category fires on
fewer samples, and one datalake sample lost its only evidence -- bazaar lost
none. Against that, benign No Evidence rose 0.4 and 1.4 points. One malware
sample for two corpora of benign accuracy is the trade, and it is a good one.

**Meanwhile the module still cannot see 8 of these samples.** Three framings
have been tried -- API rarity, capa-within-managed, and this -- and none has
produced a category. That is a legitimate end state under the project's own
standard, and better recorded than papered over.

The metric is the fraction of the `#Strings` heap that no compiler and no
developer would emit: a character outside the identifier set, or four letters
without a vowel. Obfuscators rename every type, method and field; benign
assemblies do not.

**The benign floor is measured, on 592 binaries.** 67 are managed, 58 IL-only,
39 measurable at 50 identifiers or more. Highest benign fraction is 0.099 on
`protobuf-net.Core.dll`, and **nothing fires at any cut from 0.10 upward**. No
protector markers appear in benign at all.

Two separations that had to be made rather than thresholded around. Mixed-mode
C++/CLI carries mangled native symbols in `#Strings` -- `mfcm140u.dll` reads
0.201 unreadable and is entirely legitimate -- so IL-only is a precondition, not
a penalty. And a satellite resource assembly with five identifiers reads 0.200
on a single generic name, so a 50-identifier floor separates a measurement from
arithmetic on too few names.

**Measured on the guest, then shipped as `obfuscated_managed_code`.** 47.6% of
the malware corpora is managed against 11.3% of benign, but only 6.2% has
renamed identifiers -- so managed malware here is not mostly obfuscated, it is
invisible because nothing read CLR metadata at all. Where renaming does occur it
separates completely:

    unreadable-identifier fraction     benign(592)   malware(227)
    ─────────────────────────────     ───────────   ────────────
    measurable managed assemblies              39            99
    >= 0.20                                     0            10
    highest observed                        0.099         0.776
    names a protector outright                  0             4

**The threshold is not load-bearing.** Benign tops out at 0.099 and the five No
Evidence samples this recovers sit at 0.298, 0.267, 0.255, 0.239 and 0.228, with
nothing in either band between. Any cut from 0.10 to 0.22 gives identical
coverage; 0.20 is twice the benign ceiling and clears the lowest true positive
by 0.028. It costs four corpus-wide detections against 0.10, all on samples YARA
or capa already catch.

Two preconditions rather than thresholds: IL-only, because mixed-mode C++/CLI
carries mangled native symbols (`mfcm140u.dll` reads 0.201 and is legitimate),
and a 50-identifier floor, because a satellite resource assembly reads 0.200 on
one generic name.

**A named protector does not fire it alone.** Dotfuscator and SmartAssembly are
products people buy; 0 of 39 benign managed assemblies is not a false-positive
rate for protected commercial software, it is the absence of that software from
the corpus. The marker explains a finding rather than making one, and the same
reasoning keeps the category out of `strong`.

Benign cost: **0.0% on both corpora**, bands unchanged at 286/4/2 and 271/28/1.

**Do not lower the entropy threshold, and the reason matters more than the
decision.** 8 of the 22 sit at executable entropy between 7.0 and 7.5, just
under the cut, and the benign curve is nearly flat -- 0.7% / 0.3% at 7.0
against 0.3% / 0.0% at 7.5 -- so moving it would be cheap. It is still tuning:
the justification would come from *these 22 samples*, not from the separation,
and the curve gives no independent reason to prefer 7.0. The benign corpora
also under-represent the installers where legitimate packing lives, so the
conservative cut is the one whose blind spot is known. Revisit it from a corpus
of installers, never from the band.

**3 samples in the band carry a signature that verifies, and the reason may be
that they are not malware.** Across both corpora five samples verify, all in
datalake, none in bazaar. The signers are real companies: `NetSupport Ltd`,
`AVG Technologies USA, LLC`, `Sahlmen Software AB`, `A-LINE PIPE TOOLS INC.`,
and one in Wuhan. None matches a YARA rule, and the A-LINE one produces **zero**
capa rules -- signed, inert, and unremarkable, which is the profile of a clean
file rather than a quiet one.

**Both corpora are `datalake.abuse.ch/malware-bazaar/daily/`** -- the same
MalwareBazaar, by daily archive rather than API. That is a *submission* feed:
what people uploaded believing it malicious. It legitimately contains dual-use
tooling (NetSupport Manager is a commercial remote-control product abused in
intrusions) and occasionally files that are simply not malware.

**The reports say "presumed benign, not verified" of the benign corpora and say
nothing of the kind about the malware ones.** That asymmetry is wrong and it
matters here: some of the 18 the module cannot see may be samples with nothing
to see. Every malware rate in this file is a rate over *presumed* malware, and
should be read that way.

**The lookup ran on 28 Aug -- `scripts/refresh_virustotal.py` -- and the answer
is three-two against the comfortable reading.**

    VT name               signer                     detections
    ──────────────────    ───────────────────────    ──────────
    CALC.EXE              A-LINE PIPE TOOLS INC.             56
    (hash-named)          a company in Wuhan                 40
    SecureViewXLS.exe     Sahlmen Software AB                33
    AVG Secure Browser    AVG Technologies USA                3
    pcichek.dll           NetSupport Ltd                      1

**Three are signed malware with abused certificates, not contamination.** The
prediction offered before the run was that `A-LINE PIPE TOOLS` -- signed, zero
capa rules, zero YARA -- would come back clean. It is the *most detected of the
five* at 56 engines, named `CALC.EXE`, and the static module sees literally
nothing in it. That is the clearest single example in the project of a sample
static analysis cannot reach: no packing to measure, no metadata to doubt, a
signature that verifies, and no capability capa recognises.

**Two are effectively clean**, at 1 and 3 detections against 70-odd engines,
which is false-positive noise: `pcichek.dll` from NetSupport and AVG's own
browser. So the corpus does carry a little of what a submission feed carries --
roughly 0.9% of 227 -- and the "presumed malicious" caveat above stands. But it
explains two samples, not the band.

**The reframe was half right and the half that failed is the important one.**
Some of the band is files with nothing to detect; most of it is malware with
nothing *statically* detectable, which is a different and harder fact. It is
also the strongest argument in this file for the dynamic side: three of these
would need to run before anything could be said about them.

VirusTotal remains outside the verdict model -- `virustotal.json` is updated and
no rate in this file moves, because letting a third-party opinion raise or
suppress a local observation is the error the category set was rebuilt to avoid.

**One sample is a collection gap** -- capa did not run on it. That is one
re-run, not a category.

**A false lead, recorded because it looked good.** Three of bazaar's five claim
a `CompanyName` of random characters (`2I?F=JC22>;A8;C9D;>HAE4` and two like
it), which reads like a cheap high-precision signal: benign software does not
ship unpronounceable vendor names. Datalake has **none** -- its seventeen claim
`Opera Software`, `Avira GmbH`, `NetSupport Ltd`, `Purity`, `China`. Three
samples in one corpus is a quirk of one family, and building a category on it
would be fitting the test set with a straight face.

**Worth an eyeball:** one datalake sample claims `Microsoft Corporation` and its
signature *verifies*. Either a clean file that arrived in a malware corpus, or
something signed with a certificate that should not have signed it.

**The benign corpus was widened on 28 Aug, 592 -> 1,492**, and the result is
worth reading carefully because the headline is not the point.
`scripts/benign_survey.py` adds 900 binaries across 105 vendors, collecting only
signing, PE metadata and CLR -- fourteen minutes rather than most of a day,
because none of the three questions it answers touches capa, YARA or IOCs.

**What it found was a false-accusation class, not more vendors.** The wider
corpus qualified `ffmpeg` on the two existing rules at 7 of 7 signed -- and 0 of
the 7 signed by FFmpeg. OBS Project, Chengdu Yiwo Tech and Microsoft 3rd Party
had signed them, because FFmpeg is redistributed far more than it is shipped;
listing it would have accused every unsigned FFmpeg build, the ordinary case, of
impersonation. `patriot`, `insecure` and `epic` failed the same way. So there is
now a third qualifying rule -- **the vendor must sign its own releases** -- and
the narrow corpus could not have shown it, because it contained none of them.

`_ALWAYS_SIGNS` goes 8 -> 13 over 1,219 samples. Benign cost unchanged at 0.0%
on both corpora; malware unchanged at 9 and 8. `nvidia` is a deliberate
conservative loss, out at 91.7% self-signed once WHQL co-signing is counted.

**A second machine closed three of the four misses -- 28 Aug.** The bound was
never the method, it was one machine's installed software. A throwaway VM with
Adobe Reader, Opera and Avira installed
(`scripts/bootstrap_vendor_survey.ps1`), surveyed and merged with
`derive_signers.py --survey`, takes `_ALWAYS_SIGNS` from 13 vendors to 17 over
1,593 samples:

    added     adobe, avira, mcafee, opera, python
    removed   oracle

`mcafee` arrived uninvited, bundled with Adobe Reader, and qualified on its own
measurement. `python` qualifies at exactly 4 of 4, which is the thinnest
possible pass and worth knowing.

**Adding data removed a vendor, which is the derivation working.** `oracle` was
12 of 12 signed on the narrow corpus and is **21 of 23** on the wide one --
91.3%, under the bar. It comes out, and three datalake samples that claim
`Oracle Corporation` stop being caught. A list that only ever grows is a list
being curated rather than derived.

**Measured on all five corpora, the change is close to a wash, and the
accounting is worth stating in full.**

    deceptive_file_identity      family   6-year   total
    at 13 vendors                     9        8      17
    at 17 vendors                    11        7      18

    bands, No Evidence           family   6-year   total
    at 13 vendors                     2       16      18
    at 17 vendors                     2       17      19

Four vendors added catches two more in bazaar; one vendor removed loses one in
datalake, and that sample had `deceptive_file_identity` as its only evidence, so
the band grows by one. One more detection, one more sample nobody can see.

**That is not a reason to keep Oracle.** It ships unsigned 2 times in 23 -- the
rule exists so that an unsigned copy of ordinary software is not accused, and
Oracle's own releases are ordinary software. Keeping it because removing it
costs a detection is how a derived list becomes a curated one, and the benign
cost of the whole change is **0.0% on all three benign corpora**, unchanged.

**Windows Defender cannot be added, and the reason is not a missing root.**
This section said it was one, twice. Checked on 28 Aug: `C:\Program FilesWindows Defender` holds 40 binaries and *is already a survey root*, and every
one of them carries `CompanyName: Microsoft Corporation`. Nothing legitimate on
this machine claims `Windows Defender` as a company -- `windows` appears as a
vendor key on **0 of 1,079** surveyed binaries, against 755 for `microsoft`.

So the malware claiming `CompanyName: Windows Defender` is claiming a *product*
name as a company, and `_ALWAYS_SIGNS` can never hold it: the list is derived
from what benign software claims, and no benign software claims that. Adding the
`ProgramData` root would have changed nothing, and the two earlier notes here
predicting otherwise were wrong.

**It is a different rule, not a longer list.** `_ALWAYS_SIGNS` asks *does this
vendor always sign*; catching this needs *is this a vendor at all*. That is
derivable in principle -- a company name absent from every benign corpus -- but
so are the names of every small legitimate vendor nobody here has installed, and
the false-positive population is unbounded. Not attempted.

**The installer blind spot was closed on 28 Aug, and it said no.**
`high_entropy_sections` was withheld from `strong` on the stated grounds that
both case corpora are *installed* software and contain none of the installers
where legitimate packing lives. A 210-binary installer corpus now measures that
population:

    population              n     >=7.0     >=7.2     >=7.5
    ─────────────────    ────    ──────    ──────    ──────
    installed software    900     0.11%     0.00%     0.00%
    installers            210     1.90%     1.90%     0.95%

Two signed, entirely legitimate installers cross the shipped cut:
`uninstall.exe` from Indigo Rose Corporation at 7.93 and `Docker Desktop
Installer.exe` at 7.74. **`strong` stays off**, now for a measured reason rather
than an assumed one -- it would carry both to Corroborated alone, where
non-strong leaves them at Single Observation. The 7.5 cut is re-confirmed at the
same time: at 7.2 the installer rate doubles to 1.90% as two Armoury Crate
binaries (7.49, 7.46) join.

    G:\installer-survey.json      75 from the package caches and Windows\Installer
    G:\installer-survey-pf.json  135 installer-named under Program Files

**Read it as directional, not as a rate.** `--name-glob` selects on what a
publisher called the file, which is a claim: an installer named `app.exe` is
missed and a library named `installer.dll` is drawn. 210 samples from one
machine settles whether the population exists -- it does -- and not what its
rate is. `Downloads` would roughly quadruple it and is deliberately excluded,
because on this bench it holds the malware corpora.

The other two calibration questions came out clean. The managed baseline more
than tripled, 39 measurable assemblies to 129, with nothing at or above the 0.20
cut and no named protector in any of 161 managed binaries. Executable entropy:
one sample of 900 above 7.0, none above 7.2.

**3. The filename half of `deceptive_file_identity` is still unreachable**, and
that is worth keeping written down even though the category now fires. The
vendor claim was folded in here rather than made a seventh category because it
is the same question -- *what is this file claiming to be, and did someone
author the claim?* -- and one claim should be charged once.

Not dead code — all three predicates work. All 227 malware samples are named
`<sha256>.exe` (100%, both corpora), and `_sample.json` shows they were already
hash-named on disk, so the authored name was destroyed at download time,
upstream of the corpus builder. Both recovery paths are closed:
`OriginalFilename` appears in none of the 819 cases, and VirusTotal
`meaningful_name` is empty everywhere (`VT_API_KEY not set`). Measuring it at
all requires acquisition to preserve the delivered filename. One note for the
rebuild: System32's own `AppHostRegistrationVerifier.exe` declares
`OriginalFilename` `AppHostNameRegistrationVerifier.exe`, so a naive
name-mismatch rule false-positives on Microsoft.

**4. `embedded_network_indicators`: the narrower question was measured, and it
needs a better parser after all.** The heading here said the opposite for a
week.

Excluding hosts by benign prevalence -- the derive-don't-choose method that
built `_ALWAYS_SIGNS` -- takes the category from **1.0x to 2.5x**:

    host seen by >= N other benign      benign   malware    lift
    ──────────────────────────────     ───────   ───────   ─────
    (no exclusion, as shipped)           76.7%     75.3%    1.0x
    1, hosts only                        14.2%     35.7%    2.5x
    1, hosts and IP literals             18.9%     41.0%    2.2x
    2, hosts and IP literals             24.7%     42.3%    1.7x

Scored leave-one-out, because the benign corpora built the prevalence table and
crediting each sample for its own hosts reads 5.6x. **2.5x is a real
improvement and still below this project's own bar** -- `persistence` was
rejected at 4.2x and `host-interaction/process/inject` at 1.4x. The category
stays in `CONTEXT_ONLY_CATEGORIES`.

**What the measurement actually found is that the extractor emits things that
were never network destinations.** The most common "domains" in every corpus:

    benign    schemas.microsoft.com, crl.microsoft.com, ocsp.digicert.com,
              cacerts.digicert.com, and `ocsp.digicert.com0a` -- ASN.1
              trailing bytes read as part of the hostname
    malware    myapplication.app in 50 of 127 bazaar samples, tempuri.org,
               nsis.sf.net, www.w3.org

XML namespace declarations, certificate-chain fragments, installer boilerplate
and a framework placeholder. One Program Files sample yields
`cn.cs.da.de.el.en.es.fi.fr.he.hu.is.it.ja.ko.nl.no` -- a language-code list
with seventeen labels. **A category cannot be narrowed onto data this noisy**,
and the honest order is: fix `step_iocs` to reject what is not a hostname, then
re-ask the question against what survives.

**The parser was fixed on 28 Aug and it was a smaller bug than this said.**
`ocsp.digicert.com0a` is already rejected by the current code -- that junk is
stale corpus output, not a live defect. And `schemas.microsoft.com`,
`www.w3.org` and `tempuri.org` are *correctly extracted hostnames*: the
extractor is right that they are hosts, and the category is wrong to read an XML
namespace declaration as a network destination. That is not a parser question.

What was a real defect: a .NET namespace has the same shape as a hostname and
the extractor folded the case away before anything could tell them apart.

    au-v20.events.endpoint.security.microsoft.com       a real Defender host
    microsoft.codeanalysis.csharp.symbols.metadata.pe   a C# namespace

Six labels each, both with a real suffix -- `.pe` is Peru -- so nothing
structural separates them. `_looks_like_namespace` handled the two-label case
and its docstring claimed to check "an internal capital in the original", which
it could not: the call site lowercased the match first. Now it gets the unfolded
string, and a name with three or more labels and two or more capitalised ones is
code. Two rather than one, so `Discord.com` in a message is still a host.

It drops 18 distinct strings across the corpora and moves the firing rate on
System32 from 9.9% to 8.6%, and not at all elsewhere. Correct, and small.

**All five corpora were re-extracted against it and the question was re-asked
on clean data. The answer did not change.** Prevalence exclusion goes from 2.5x
to **2.7x** -- still far below the 4.2x at which `persistence` was rejected --
so `embedded_network_indicators` stays in `CONTEXT_ONLY_CATEGORIES`, now for a
measured reason rather than a suspected one.

That is the honest end of this item. The noise the category drowns in is not
mostly malformed extraction: it is `schemas.microsoft.com` and
`ocsp.digicert.com`, real hosts named in XML namespaces and certificate chains,
which a parser has no business rejecting. **Containing a hostname is a property
of software**, and no amount of cleaning changes that.

`scripts/refresh_iocs.py --skip-strings` re-extracts from the dump already in
each case, which is what a change to `ioc_extract.py` needs and what let this run
on a host with no `strings` binary at all.

**A correction to what this section said an hour earlier.** Two of the four
"real signal" hosts named below were Go runtime symbols: `reflect.Value.Int`
appears in every Go binary, and it survived prevalence exclusion only because
benign Go binaries are rare in these corpora. `ip-api.com` and `discord.com`
stand. A host surviving an exclusion built from *this* benign population is
evidence about the population as much as about the host.

**5. The README section is published and current.** Eight categories with the
closing numbers, both halves of the `stripped_metadata` correction, and the 19
that still resist everything stated as the number to compare against -- not the
3 the module reported before any of this, which counted samples covered by a
signal that did not exist. Revisit it when item 1 or 2 moves a figure.

**6. Other modules have false-positive rates only.** `extension`, `spec`, `api`.
For `spec` and `api` a "true positive" means a real exposure found in the wild,
which is a different sourcing problem; `extension` malicious samples are
delisted.

### Item 1 — the sample for gap 4, chosen by measurement — 31 Aug

**The question was wrong, and that is why two detonations failed.** Both samples
were picked for *detecting virtualisation* — FormBook by module hash, and
`a6a86646…` because a sandbox had flagged it as reading VirtualBox ACPI keys —
and both produced `artifacts_read: 0`. The detector counts only `vm_specific`
*registry* reads, so the question it needs answered is not "does this sample
detect a VM" but **"does it detect a VM through the registry"**. Those are very
different populations, and `scripts/vm_check_candidates.py` measures how
different over all 227 malware cases:

    of 227 malware cases (226 with strings, 202 with capa)
    ─────────────────────────────────────────────────────────
    capa anti-VM rule fires                            49
      ...with no VM check visible in its own bytes     38
    names a VM-only registry key                        1   <- can exercise gap 4
    identity keys only                                  1
    checks by other means only (WMI, device, CPUID)    15

**capa's anti-VM namespace is not a proxy for this, and reaching for it is how
the last two samples were chosen.** 38 of the 49 show no VM check of any kind in
their own strings — no registry key, no WMI class, no device path, no CPUID
literal. `reference anti-VM strings targeting Xen` accounts for 22 of the 49 and
20 of the 38: it is matching the substring. That is the same shape as the two
"real signal" malware hosts that turned out to be Go runtime symbols — a rule
that fires on a token every large binary happens to contain.

**One sample qualifies, and it qualifies on its own code.**
`ce0d08be516376f5decc3bf6d8970fa493c925bc013a088c2a4eb8ed9f9fc3f1` (bazaar,
case `b526eab6`). A 2.9 MB .NET RAT, Costura-packed, importing nothing but
`mscoree!_CorExeMain`, `.text` at 7.808 entropy, 0 of 1,545 YARA rules. Its
strings carry the check end to end:

    method names      CheckVirtualBox, CheckVMWare, CheckRegistryKeys,
                      OpenRegistryKey, IsSandboxie
    VM-only keys      SOFTWARE\Oracle\VirtualBox Guest Additions
                      SOFTWARE\VMware, Inc.\VMware Tools
    identity keys     HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\...\Logical Unit Id 0
                      SYSTEM\ControlSet001\Services\Disk\Enum, SystemBiosVersion
    compared against  VIRTUALBOX, VMWARE, vmware, virtual, innotek
    and by WMI        SELECT * FROM Win32_ComputerSystem
                      SELECT Description FROM Win32_VideoController
    and it reports    "Client … was a virtual machine!"

That last string is the reason to expect a *usable* run rather than a bail: the
sample tells its operator it is virtualised. **This is the confirmation the plan
asked for — "a sample confirmed by reading its code, not by a sandbox
signature" — and it is also the sample being managed code**, which is where 59%
of what static cannot see already lives.

**Pre-flight, and the first item is the one that can waste the detonation.**

1. **Run Procmon under a different filename.** `procmon` is in this sample's
   own process-name list, alongside `taskmgr`, `procexp`, `processhacker` and
   `perfmon`; a second list holds `x64dbg`, `windbg`, `dnSpy`, `wireshark`,
   `fiddler` and `sbiedll.dll`. `start_procmon_capture` takes the executable
   path as an argument, so a renamed copy costs no code change, and
   `/Terminate` and `/OpenLog` work the same from it. Concretely: copy
   `tools\Procmon64.exe` to something else on the guest and point
   `dynamic_procmon_path` -- the GUI's Procmon field, saved in `config.json` --
   at the copy. Do not run the network tools under their own names either.
2. **Confirm the config in force is `dynamic_registry_reads.pmc`.** It is the
   default and `describe_procmon_filter` reports `captures_registry_reads`, but
   a saved `dynamic_procmon_config_path` still wins. Checked on the host today:
   `dynamic_default.pmc` includes 16 operations and captures no registry read;
   `dynamic_registry_reads.pmc` includes 18, adding `RegQueryValue` and
   `RegOpenKey`.
3. **The guest additions are installed, and nothing in this project removes
   them.** `vm_hygiene.ps1` only *detects* a VM so it can refuse to run on a
   real workstation; it disables updaters and telemetry and touches no
   guest-additions key or service. `vm_artifact_reads.py` said the opposite in
   a docstring and a test comment, both corrected today. So the VirtualBox read
   is expected to return `SUCCESS` and the sample is expected to learn where it
   is — which is the run we want, because it exercises `artifact_found: True`.
4. **`git pull` on the guest**, as ever.

**Pre-registered prediction, written before the run.**

`collect_vm_artifact_reads` reports `collection_available: true` and at least
two `vm_specific` hits attributed to the sample's own tree — the VirtualBox
Guest Additions install key at `SUCCESS`, the VMware Tools install key at
`NAME NOT FOUND` — plus `identity_surface` hits on `SystemBiosVersion` and the
SCSI device map. `correlate_vm_check_with_silence` returns
**`checked_then_active`**, with `sample_events_after_check` in the hundreds or
thousands rather than near 10.

If it comes back `checked_then_quiet` with a small count, **the first thing to
rule out is our own Procmon**, not the sample's judgement: a blocklisted process
name produces a bail that looks exactly like a decision about the hypervisor.

**What this run can and cannot settle, said now rather than after it.** It can
prove the collection path end to end — a `vm_specific` read reaching the
detector for the first time — and it can rule `QUIET_EVENT_THRESHOLD = 10` out
as too high if the active count lands where predicted. It **cannot calibrate
the threshold**, because the threshold separates a bail from a pause and a
`checked_then_active` run only bounds the active side. Calibration needs a
sample that bails, and this corpus does not obviously hold one. Recording that
in advance, because the temptation after a run that works is to call the
placeholder settled.

### Item 1 — the run, and what it actually measured — 31 Aug

**The prediction was wrong.** Published before the run: `checked_then_active`,
at least two `vm_specific` hits, `sample_events_after_check` in the hundreds or
thousands. Returned: `no_vm_check`, `artifacts_read: 0`. Writing it down first
is what makes the rest of this section a result rather than a story.

**What worked, and three runs had failed at it.** The collection path is proven
end to end for the first time in this project:

    collection_available            true
    lineage_resolved                true
    reads_in_stream               171,728
    sample_reads                    2,664
    background_artifact_reads           3

`dynamic_registry_reads.pmc` captured the reads, and `rf_trace64.exe` was not
spotted — the sample ran to completion with Procmon resident. **The markers also
matched real data**: three VM-artifact reads were classified correctly out of a
live stream, which rules out the failure mode this package fears most, where 46
markers were once written regex-style and matched nothing for the life of the
project.

**Three explanations were raised and all three were killed by measurement.**
Recorded because the ruling-out is most of this session's value.

*It died on startup* — no. `exit_code: 0`, no crash, 7 process creates, 82
high-signal file writes, 23 dropped files, a persistence hit, a new autoruns
entry, 7 memory YARA matches across 7 dumps including one memory-only rule.
The run scored **Likely Malicious, 140, High**.

*The relaunched copy fell outside the resolved lineage* — no. `708 -> cmd.exe
9476 -> copy 10208` is an unbroken parent chain. Re-running
`collect_vm_artifact_reads` with `descendant_pids=None`, which counts every
process on the machine, returned the same answer: the only VM-artifact reads in
the entire stream were three `identity_surface` reads by `svchost.exe` 3408 --
`SystemManufacturer`, `SystemProductName`, `BIOSVersion`. Windows reading its
own machine identity.

*It short-circuited on WMI* — no. Only `wmiprvse.exe` loaded `fastprox.dll`,
`wbemcomn.dll`, `wbemprox.dll` and `wmiutils.dll`; neither sample process loaded
a WMI client library. And the sample's tree made **zero network events**, so it
never reached a check-in either.

**The answer was in the `schtasks` command line.**

    11:16:59.3  python.exe  ->  sample (708)
    11:17:00.7  708         ->  cmd /c "...\AppData\Roaming\Temp\cleanup_...bat"
    11:17:07.7  cmd (9476)  ->  timeout /t 2 /nobreak
    11:17:09.8  cmd         ->  "...\AppData\Roaming\PlatformRuntime\ce0d08be....exe" (10208)
    11:17:09.8  cmd         ->  timeout /t 1 /nobreak      then deletes the original
    11:17:21.8  10208       ->  schtasks /create /tn "ce0d08be..." /sc ONLOGON
                                  /tr "...\PlatformRuntime\ce0d08be....exe" /rl HIGHEST /f

`/sc ONLOGON`. The copy installed the task, went quiet, and made no network
attempt for the remaining 880 seconds — it had finished its job. **This run
observed the installer. The payload runs at next logon.** The stage that would
check for a VM, and report `"Client ... was a virtual machine!"` to its operator,
is sitting in a scheduled task waiting for a trigger a single-boot detonation
never produces. The 900-second window was irrelevant; no amount of waiting fires
an `ONLOGON` task.

**Gap 4 is therefore not declined, and this section previously read as though it
would be.** The sample selection was sound -- the check is in the code, and the
sample ran -- but *names a registry key in its bytes* predicts capability, not
execution, and that is the correction to carry forward. What is left is a cheap,
specific, unattempted experiment that this run defined exactly:

> Detonate, let it persist, then **log off and back on with a fresh capture
> running** under `dynamic_registry_reads.pmc`. The `ONLOGON` task launches the
> copy and the payload stage is finally observed. The sample is already
> installed on the guest, so the expensive half is done.

Two things to expect there. The orchestrator starts and stops Procmon around the
run, so this needs a **second capture after the logon** rather than one
continuous one -- simpler than Procmon boot logging and needs no code. And
`/rl HIGHEST` means the task runs **elevated**, which our run was not; a
different privilege context can change what a sample does.

**The limitation this exposes is bigger than gap 4, and no report currently
states it.** The pipeline detects persistence -- the autoruns diff and the task
diff both caught this one -- but it cannot observe **what the persisted thing
does**. Every detector in the dynamic side watches one boot, and a payload
behind `ONLOGON`, a logon script, or a scheduled trigger is outside all of them.
This run scored 140 on the installer alone, which is the good news; the payload
was never watched, which nothing in the output says. Exit criterion 1 asks for a
named reason wherever something is built and unproven, and for this class of
sample the reason is the observation model rather than any individual detector.

**`background_hits` is now returned from `collect_vm_artifact_reads`**, beside
`windows_response_hits` and `routine_subpath_hits`. It was built for hypothesis
2, which was wrong -- but a count that cannot say *which process* is a gap
whatever the hypothesis, and returning the rows is what let this run be settled
from disk instead of by a second detonation.

### Item 1 — the logon run, and gap 4 declined with a reason — 31 Aug

**The payload stage was observed in full, and it does not check the registry.**
The ONLOGON task fired at 16:22:07, the copy ran resident for over an hour
elevated, and Procmon boot logging captured all of it. The sample's own process
made **967 registry reads and none named a VM artifact**:

    PID 3760, C:\Users\adam\AppData\Roaming\PlatformRuntime\ce0d08be....exe
    ─────────────────────────────────────────────────────────────────────
    RegOpenKey        509        Load Image         62
    RegQueryValue     458        CreateFile        396
    RegSetValue         8        Process Create      1
    VM artifacts        0

The last row is the result and the rows above it are what make it one. A zero
from a process that produced 1,438 events, loaded 62 images and started under
the capture is a statement about the sample; a zero from a process the capture
never saw would have been a statement about the pipeline. That control is the
only reason this section can be written.

**Four hypotheses, all killed by measurement, across two runs.** The sample has
`CheckVirtualBox`, `CheckVMWare` and both guest-tools install keys in its bytes,
and never executes them. It did not die on startup; the copy did not fall
outside the lineage; it did not short-circuit on WMI; and it is not simply the
installer stage — that was the ONLOGON finding, and this run watched the stage
that finding predicted.

**What the logon run cost and what it produced.** Boot logging captures with no
capture-time filter: 4.2 GB of `.pmb` in 65 minutes, a 1.67 GB `.pml`, and a
703 MB CSV *with the registry-read filter applied at export*. That is 65 MB per
minute, and `parse_procmon_csv` cannot hold it -- `scripts/vm_reads_from_csv.py`
streams instead. **Boot logging is how you prove a payload stage exists; it is
not the instrument for watching one.**

**So the instrument was built: `dynamic_analysis/logon_capture.py` and
`scripts/logon_capture.py`, 11 tests.** A filtered Procmon capture that is
already running when the user logs on.

The task triggers on **`ONSTART`, not `ONLOGON`**, and that is the decision the
whole thing turns on. Racing the sample's own `ONLOGON` task is a coin toss, and
losing it means missing the first seconds -- which is exactly where
`ce0d08be...` did its work both times: payload up 2 seconds after the logon,
persistence installed 12 seconds later. `ONSTART` runs as SYSTEM at boot, before
any user session exists, so there is no ordering to get right. It takes the run's
own filter, so a logon capture sees registry reads by default the way a
detonation does, and the Procmon binary is a parameter because a payload stage
that survives a logon has every opportunity to read the process list -- the CLI
warns if the name contains `procmon`.

`logon_capture.json` is written before the CSV is read: `completed: false` with a
reason when the capture did not run, and `captures_registry_reads` from the
*file* rather than the filename. A capture that never happened and a boot where
nothing happened are different results, which is the failure this whole document
keeps returning to.

**Arm it outside a run's snapshot window.** Nothing excludes analyzer-owned
tasks from `diff_tasks`, so arming between a run's before and after snapshots
reports our own collector as persistence. Before a detonation or after one
completes; never in the middle.

**A second result, and it may matter more than the first: 448 VM-artifact reads
on one ordinary boot, every one of them background.**

    services.exe                enumerates every VBoxGuest, VBoxSF, VBoxService,
                                vmbus and vmicvss key -- Start, Type, ImagePath,
                                Tag, DependOnGroup, dozens each
    MpDefenderCoreService.exe   probes \Performance under every VM service
    WMIADAP.EXE                 the same
    Explorer, winlogon,         VBoxSF\NetworkProvider
    powershell x3
    VBoxService, VBoxTray       the Guest Additions install key, naturally

`ROUTINE_SUBPATH_MARKERS` already sets aside `\vboxsf\networkprovider` after a
run where PowerShell produced four such hits. This measures how far short of the
real background that goes. **`vm_specific` is not self-sufficient: it carries a
background of roughly 450 reads per boot, and lineage is doing all of the
work** -- which is exactly the thing a logon-triggered payload takes away.

The widening this justifies is specific and is **recorded, not shipped**:
service-config values (`\Start`, `\Type`, `\Tag`, `\Security`, `\DeleteFlag`,
`\DependOn*`, `\ObjectName`) and `\Performance` subkeys are SCM and WMI
housekeeping and are never a VM check, which reads key *existence* or
`Version`/`InstallDir`. Widening an exclusion list can only ever hide a hit, and
there is no run with a known positive to measure the cost against. It waits for
one.

**Gap 4's active detector is declined, and exit criterion 4 is satisfied.** Not
unbuilt: `correlate_vm_check_with_silence` exists, carries 14 passing tests, is
wired into `orchestrator.run`, renders as a `card-alert`, and its collection
path is now proven end to end -- 171,728 reads on the first run, 3.39 million on
the second. It is declined because the input does not occur, and both halves of
that are measured:

    of 226 malware samples with strings, naming a VM-only registry key      1
    of 3 samples detonated for this, making a vm_specific read              0
    background vm_specific reads by Windows itself, per ordinary boot     ~450

The surface is rare in the field, and where it does appear it is swamped by the
operating system unless lineage holds -- and the payload class most likely to
use it is the class lineage cannot attribute.

**One thread stays open, and this sample cannot close it.** The check may sit
behind a *completed* C2 handshake: `"Client ... was a virtual machine!"` is
operator-facing panel text, so it plausibly runs while building a check-in. Two
things about that were measured after the run and the second corrects a claim
made an hour earlier in this session.

The protocol is **server-speaks-first**. A hand-run listener on **port 7372**
accepted the connection; the client connected, sent nothing, waited and timed
out. Getting past that needs enough of the protocol reversed to send a plausible
server hello, which is a project and is out of proportion to one context-only
detector.

And **the C2 is hardcoded `127.0.0.1`, so this build has no infrastructure at
all.** FakeNet was started to resolve the beacon's hostname and logged five DNS
requests, all `svchost.exe` fetching digicert, bing and Microsoft telemetry --
**the sample made none**, because it never had a name to look up. `127.0.0.1` is
in its strings, and the only other IP-shaped strings in the file are .NET
assembly versions. The ~200 sockets left in `Bound` were a beacon loop retrying
loopback, and it connected the instant something listened there.

So this is an unconfigured builder-default build, and it was reported here as
having "given up its infrastructure", which it never had. Any C2-gated
experiment on this family needs a *configured* sample; `ce0d08be...` is a dead
end for it, and the port is the only part worth carrying forward.

### Traps this cost a day to find

Each of these produced a plausible number rather than an error, which is why
they survived:

- **A collector that fails must report `unknown`, not clean.** Four instances
  now: `strings` was never installed (821 cases, `strings.txt` 0 bytes), capa
  was missing from a non-activated venv (194 of 229 malware samples), FLOSS
  deadlocked, and the version-info block was **never written by anything** —
  read by the categoriser, produced by no collector, and constructed by hand
  only in the tests, which is exactly why they passed throughout.
- **A consumer reading a field no producer writes fails silently and
  plausibly.** `stripped_metadata` did not error and did not report `unknown`.
  It degraded into a second copy of `invalid_signature` and looked like the
  strongest signal in the table. Grep for the writer, not only the reader.
- **`subprocess.run(timeout=)` kills the launcher, not the tree.** capa.exe and
  floss.exe spawn a grandchild that inherits the pipes; the drain then blocks
  forever. `static_triage_engine/proc.py` kills the tree first. A FLOSS process
  was found alive for 74 minutes against a 180-second limit.
- **`static_corpus.py --workers 4` needs 12 GB.** Four concurrent LIEF or FLOSS
  instances on packed malware exhausted 8 GB and froze the guest.
- **A run that finishes suspiciously fast is a symptom.** The malware corpus took
  20 minutes when capa was silently absent and 2 hours when it worked.
- **`preflight` in `static_corpus.py` now blocks all of the above.** Do not
  `--force` past it without writing down why.
- **Sample over the axis that matters.** Uniform draws gave 40% Microsoft in
  Program Files, a quarter azure.com in APIs.guru, and `a`-through-`M` in
  System32. Every corpus script now stratifies, and says so.
- **The baseline snapshot carried the wrong Procmon config, so the trap came
  back on every revert.** Checked 31 Aug after the logon run:
  `tooling-baseline` held `dynamic_procmon_config_path` pointing at
  `dynamic_default.pmc`, which captures no registry reads -- and a saved path in
  `config.json` beats `DEFAULT_PROCMON_CONFIG_NAME`. That is the same field that
  cost three runs, restored fresh before every detonation. **A fix applied to
  the guest is undone by the next revert; only a fix inside the baseline
  persists.** The field is now *cleared* rather than re-pointed, so the code
  default applies and stays correct if it ever changes, and the baseline was
  re-taken with it (the old one kept as `tooling-baseline-preprocmonfix`).
  Anything else configured on a guest -- a `git pull`, a renamed Procmon -- has
  the same lifetime, which is one revert.
- **Clearing that field to get the default back silently disabled the
  collection, which is the same failure through the opposite door.** The GUI
  read it as `cfg.get("dynamic_procmon_config_path", <default>)`, and a
  *cleared* key exists holding `""`, so the default is never reached. An empty
  config makes the orchestrator pass `None`, and Procmon then runs on whatever
  filter it had saved -- the state `describe_procmon_filter` reports as *"What
  was captured cannot be read from this run."* The fix for the field that cost
  three runs reintroduced the same class of bug within the hour. Both paths are
  now read with `or`, so a missing key and an empty one fall back alike.
  **"Clear it to get the default" is the obvious operator move and it was
  wrong** -- a default only reachable through an absent key is not a default.

### The correction worth remembering

`dangerous_capability` was published as "inverted, 3x", then corrected to
"inverted, 12x", and was finally neither — it separated nothing at 1.1x. Both
earlier figures were artifacts of capa being absent. The second was the worse
error: it repaired a broken measurement using a subset of the same broken data
and came out **more** confident. A claim that strengthens under correction is a
warning, not a reassurance.

`stripped_metadata` is the same lesson from the other side. Its 100%-against-0%
split was the most convincing number in the table, and it was measuring the
signature check. **A category that separates suspiciously well deserves the same
audit as one that separates suspiciously badly** — and the audit is to find the
code that *writes* the field, not the code that reads it.

**What the fix cost is the part to keep.** Corrected, the category still
separates — 77.2% and 60.0% against 0.0% and 6.0%, a better ratio than the
false one. It would be easy to record that and stop. But the same correction
took 56 malware samples from *some evidence* to *none*, because a signal that
did not exist had been the only thing covering them. The rate improved and the
module got weaker, and only one of those two facts is visible in the category
table. **A correction that makes every headline number look better has not
been fully read yet** — check what it removed, not only what it fixed.

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

### Phase 3b — extension and api — **DONE, 24 Aug**

Not the rename the design note assumed. Both analyses lived inside Tkinter
windows importing nothing but the theme, which is why neither had a test:
there was nothing importable to reach. 385 lines lifted out into
`static_triage_engine/extension_analysis.py` and
`static_triage_engine/api_response_analysis.py`, 41 tests between them.

Both scorers were **saturated** rather than merely wrong. The extension one
added source-pattern points *per file*, so a jQuery bundle reached the top band
on `fetch(` and `https://` alone — nine ordinary files scored 67 before the
manifest terms added 43 more, and every non-trivial extension rated `Critical`.
The api one had exactly one High finding and it fired on every endpoint that
sets a cookie, which is every login endpoint an analyst would test.

### Phase 4a — the combiner — **DONE, 24 Aug**

### Phase 4b — the report and the theme — **DONE, 24 Aug**

Two commits. `design_tokens.py` holds one palette both media derive from — the
"37 hardcoded colours" turned out to be **five report stylesheets**, and four of
them are gone. Then `engine.py`, `report.py` and the GUI moved onto
`combined_verdict.json`, and `scoring.py` went from 1,150 lines to 274.

### The band names — **RESOLVED, 24 Aug**

Left open at the end of 3b and closed the same day. Neither option written up
was taken: the model emits a **neutral band** and the **verdict is a sentence
derived from it** plus a domain read off which modules ran. `band` is the stable
field to compare cases on; `verdict` is prose and may be reworded without
touching anything else. See `docs/SCORING.md`.

---

## Where this leaves the project — 24 Aug

**Both build queues are empty and the bench is clean.** The dynamic pipeline was
already there; the scoring rewrite finished today; the baseline is replaced,
restored, verified and recorded. 867 tests and a standing failure this morning,
1081 now.

**Twelve silent false positives were found across five scorers**, every one of
which produced results rather than errors. The pattern never varied: an additive
model priced something it could not justify, and the pricing hid that it could
not. Asking *what claim is this, and does it stand alone* is a harder question
to answer and a much harder one to get wrong quietly.

### 1. The new model has never produced a verdict on a real sample

**This is the gap that matters, and it is the project's own standard turned on
today's work.** Every discrimination test written today is a *contract* test
against synthetic inputs — deliberately, because the sample binaries are not on
this host and a fixture suite could not have been written. That was the right
call and it leaves something unproven: 1081 tests and **zero real cases** scored
under `corroboration-v1`.

**This is blocked, and finding out how was worth the run.** Arm A was described
here as doing double duty -- answering the `bait6` question *and* being the
first real case through the unified model. It could not be the second: the
baseline is frozen at `40e19f8` and every scoring commit from `168302c` onward
is host-only, so the run reported `dynamic-corroboration-v3` and emitted no
categories at all.

Exercising `corroboration-v1` on real data therefore needs a **guest pull and
another baseline re-take** first. That is cheap -- the procedure is written down
and was executed twice on 24 Aug -- but it is a prerequisite, not a side effect
of the next detonation.

Read the first real verdict as sceptically as anything else this bench produces.
A model that has only ever been tested against inputs its author wrote is a
model whose first real disagreement is still ahead of it.

### 2. Benign rates — measured 25 Aug, and one scorer failed

`scripts/benign_rates.py` runs each categoriser over locally available software
and reports how often each category fires. Every corpus is *presumed* benign
rather than verified, and that is stated in the tool's own output: a category
firing is a finding to investigate before it is a false positive.

    module      corpus                                  result
    ─────────   ─────────────────────────────────────   ────────────────────
    static      300 System32 executables, signed        0 categories. PASS
    spec        9 local fixtures, 5 clean by label      0 on the clean 5. PASS
    extension   14 real installed browser extensions    4 at the top band. FAIL
    api         none                                    NOT MEASURED

**Static is clean across 300 binaries**, every one `No Evidence`. Three of its
six categories were exercised; the three needing capa, YARA and IOC extraction
were passed `None` and came back `unknown`, which is the honest partial report
the contract is for.

**The extension scorer failed, and finding out cost four defects.** On first
measurement **8 of 14 ordinary extensions rated `Strongly Corroborated`** --
Likely Malicious -- and one category fired on 14 of 14. The replacement for a
saturated scorer was itself saturated, one band lower.

Two were plain bugs:

- **`update_url` is universal.** Every store install has one; it is how updates
  are delivered. `external_control_surface` fired on all fourteen. Only an
  *off-store* update URL is a signal now.
- **Native messaging was counted twice** -- as a source string in
  `external_control_surface` and as a permission in `high_risk_permission`.
  Two categories firing on one fact is manufactured corroboration, which the
  model exists to prevent.

Two were miscalibration:

- **`declarativeNetRequestWithHostAccess` and `webRequestBlocking`** were in the
  reserved-capability set. They are MV3's *standard* content-blocking APIs and
  put two ordinary ad blockers at the top band.
- **`eval(` in vendor bundles** fired `dynamic_code_execution` on 7 of 14. Under
  MV3 the default policy forbids `unsafe-eval`, so that code cannot execute --
  the policy is the claim now and the source corroborates it.

And the broader miscalibration: **`strong` was set far too freely.** Four of
five categories could be emphatic on modest evidence, in a population where
broad access is ordinary. Only two conditions survived: two reserved
permissions together (1 of 14) and a broad `externally_connectable` (2 of 14).

That halved the top band, 8 to 4. **It did not fix it**, and the tuning stopped
there deliberately -- fitting five thresholds to fourteen samples is the
additive model's failure in new clothes.

#### What looked structural was a biased sample — corrected 25 Aug

The conclusion recorded above was that the five extension categories are facets
of one property, that corroboration across facets is not corroboration, and that
no threshold repairs it. **That was drawn from fourteen extensions installed on
this bench, and it was wrong.**

The extensions on a working machine are the ones somebody chose to install. That
population skews hard toward the capable — ad blockers, a password-adjacent
tool, `debugger` for one of them — which is exactly the property the categories
fire on. Measured against **394 extensions sampled at random from the store's own
sitemap**:

    band                       count    rate
    ─────────────────────────  ─────   ──────
    No Evidence                  287    72.8%
    Single Observation            79    20.1%
    Corroborated                  24     6.1%
    Strongly Corroborated          4     1.0%

    category                  present  emphatic
    broad_host_access           20.1%      --
    credential_surface           7.4%     2.8%
    external_control_surface     3.0%     0.0%
    high_risk_permission         2.5%     1.5%
    dynamic_code_execution       2.0%     1.0%

**The four at the top band do not read as false positives.** One holds `debugger`
with `cookies` across every site; another is exam-proctoring software with
`desktopCapture`, `browsingData` and `history`. Those are the extensions that
should attract attention. And "presumed benign" is a presumption — the store is
known to carry malicious extensions, so a 1% top band is not automatically a 1%
error rate.

#### The correction went further: I had over-corrected

Fixing the four defects was right — `update_url` being universal, the double-
counted native messaging, the standard blocking APIs, `eval(` in vendor bundles.
Those were correctness. **Cutting the `strong` conditions was calibration, and it
was calibrated to the biased sample.** Measured on 394:

    condition                          on 14      on 394
    ─────────────────────────────────  ────────   ───────
    content scripts on every site       43%        12.7%   correctly retired
    debugger or nativeMessaging         21%         1.5%   restored
    cookies + broad host                43%         2.8%   restored
    permissive CSP + eval in source     21%         1.0%   restored

Both conditions that survived the first cut fire in **none** of the 394. A
condition that never fires is not calibrated, it is absent.

Three are restored. The band distribution barely moved — three extensions from
Single Observation to Corroborated, the top band unchanged at four — which is
what an emphatic condition should do: separate within a band without inflating
it.

**`extension` is no longer held context-only.** `api` followed it off the
list on 26 Aug, which emptied it.

The lesson is not about extensions. **A rate measured on a convenience sample is
not a rate**, and the convenience sample here was three hundred metres from a
real one: the store publishes its whole catalogue in `robots.txt`.

#### The api scorer is unmeasured, and named as such

No corpus of real HTTP responses exists locally. `benign_rates.py` reports it as
`NOT MEASURED` rather than omitting it, because a scorer absent from a report
reads like one with nothing to report.

### 3. The unified report — **DONE, 25 Aug**

`static_triage_engine/verdict_report.py`, 16 tests, and the window now calls it
instead of building the page itself. 150 lines out of the Toplevel.

**The order is the argument**, and it is close to the reverse of what was there.
A reader meets: what we concluded, then why — every category that fired, in the
prose its module wrote to be read aloud — then what we could not see, then what
somebody else thinks, and only then how much happened.

The page it replaces opened with a twelve-row key/value table in which the
verdict sat between "Case Path" and five per-module subscores from the retired
additive model. **The evidence appeared nowhere at all.** A number at the top is
read as the finding and prose at the bottom is read as supporting material; the
model's whole claim is that the corroboration *is* the finding and the number
describes it, so the page has to say that first. The tests pin the ordering
rather than the wording, because the wording will change and the order should
not.

Coverage sits above the per-module detail deliberately: a gap qualifies
everything after it, and a reader who meets the detail first has formed a view
by the time they learn what was missing. Every module appears even when it did
not run, because silence about a module reads as nothing to report.

A case with no verdict document renders `Insufficient Coverage` rather than a
page of blanks — an unscored case and a clean one must not look alike.

### Standing items, neither urgent

- **The `0bw` deployer.** Etherscan's API needs a paid plan for chain 97 and no
  free public node has full archive state — six probed, all partial. The
  explorer's *web UI* shows the creator and creation transaction for free and
  403s scripted access, so it is a manual read. `scripts/chain_history.py`
  carries both automated routes for whenever one becomes available.
- **The FakeNet shim for `beacon_responder.py`.** Built, never wired, needed by
  nothing currently open.
- **The stale CA.** The guest's Root store holds `141C8310…` (live) and
  `6CDD5E8D…` (21 Aug, the re-mint bug's fingerprint). Untidy rather than
  broken; remove it on the new baseline, where a mistake costs one revert.
