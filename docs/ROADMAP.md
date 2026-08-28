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

## Pick up here — 28 Aug

**`stripped_metadata` was never measuring metadata.** No collector ever wrote a
version-info block, so `_pe_string_table` returned `{}` on all 819 samples and
the category collapsed into `not trusted_signed` — a relabelling of the
signature check, which is already its own category. The collector now extracts
the block and **all four corpora are re-measured**. The 27 Aug section this
replaces is preserved in the git history.

    category                      Sys32   ProgFiles     family      6-year
    ─────────────────────────    ──────   ─────────   ─────────   ─────────
    stripped_metadata  §           0.0%        6.0%       77.2%       60.0%
    dangerous_capability           1.1%        4.0%       30.4%       18.7%
    invalid_signature              0.0%        0.0%       15.7%        6.0%
    known_malware_signature        0.7%        0.3%       16.5%       12.0%
    embedded_network_indicators †  9.9%       77.0%       71.7%       67.0%
    deceptive_file_identity ‡      0.0%        0.0%        7.1%        8.0%
    high_entropy_sections ¶        0.3%        0.0%       35.4%       28.0%
    obfuscated_managed_code ‖      0.0%        0.0%        4.7%        4.0%

    bands, No Evidence            97.9%       90.3%        1.6%       15.0%
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

**17 samples remain, and they are the honest number.** The pre-fix baseline of
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

**3 samples carry a signature that verifies.** Static analysis has nothing left
to doubt about them and the dynamic side has to take them. That is a legitimate
end state under the project's own standard, not a gap.

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

**2. Widening did not close the known misses, and cannot.** Adobe, Avira, Opera
and Windows Defender are still absent, because none is installed on this bench
at four samples or more -- tripling the corpus added five vendors and not one of
them was impersonated in the malware. The bound is what a single machine has
installed, so widening *within* it will not help again. Closing those needs a
different source: a set of code-signing certificate subjects, or a corpus from
another machine. Not a read of the test set.

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

**4. `embedded_network_indicators` needs a narrower question, not a better
parser.** It fires on 71.7% of malware and 77.0% of third-party software.
Containing a URL is a property of software. Candidate reframings: a host with no
benign reputation, an IP literal with no accompanying domain, URLs that do not
match the binary's own vendor string.

**5. The README section is published and current.** Seven categories with the
closing numbers, both halves of the `stripped_metadata` correction, and the 22
that still resist everything stated as the number to compare against -- not the
3 the module reported before any of this, which counted samples covered by a
signal that did not exist. Revisit it when item 1 or 2 moves a figure.

**6. Other modules have false-positive rates only.** `extension`, `spec`, `api`.
For `spec` and `api` a "true positive" means a real exposure found in the wild,
which is a different sourcing problem; `extension` malicious samples are
delisted.

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
