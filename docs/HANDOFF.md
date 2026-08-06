# Handoff

State of the work, for picking up in a fresh session. `docs/WORKFLOW.md` is the
run procedure; this is what is done, what is known-broken, and what is worth
doing next.

**Last updated:** 2026-08-06, after the Remcos run and the four bugs it
exposed. The commit that
last touched this file is the anchor — `git log -1 docs/HANDOFF.md` — rather
than a hash written inline, which has been stale here before.

---

## Where things stand

Two live samples have been through the pipeline end to end.

**AgentTesla** (`31a762fd…`) is the fully-worked case: dormancy, self-spawn,
unpack, C2 resolution, FTP authentication and the upload of its stolen-data
report, all captured in one run.

**A .NET loader** (`422e30ed…`, labelled Formbook by MalwareBazaar and not
otherwise attributed) has been run three times. It hollows `RegSvcs.exe` and
its stage-2 payload faults before it can decrypt stage 3, identically every
time. The payload was recovered on 05 Aug from a crash dump and is an
obfuscated 56 KB .NET assembly with no plaintext indicators — see *Loader
reference data*.

Both controls pass:

| Control | Result |
|---|---|
| `test_specs/memory_canary/` | Exactly one memory-only rule, both dumps `Frozen` |
| `test_specs/upx_control/` | 5 memory-only rules against a predicted 4 |

The UPX control's pre-flight **under-predicts by design**. It flags rules
carrying disqualifiers (`pe` module, magic at offset 0, `filesize` bounds) but
does not evaluate whether those gate the whole condition, so a rule whose
disqualifiers sit in one branch of an OR can still match. Treat its expected
list as a lower bound; more rules than predicted is a pass, fewer is a failure.

### Environment facts that are not in the code

- **Run everything on the host through `.venv`.** The global Python 3.12 is a
  partial install and silently disables YARA and psutil features. The guest's
  global Python is complete — do not add a venv there, since the GUI launches
  plain `python` and a mismatch reintroduces exactly that failure.
- **The guest needs a persistent default route** via the host-only gateway or
  FakeNet cannot intercept anything. It is in the current baseline. See the
  Hypervisor section of the README for why this does not break containment.
- **FakeNet does not restore the adapter's DNS on exit.** Between runs the guest
  points at itself with nothing listening, so DNS outside a run fails. Harmless
  during runs; confusing when testing by hand.
- **Hard power-offs corrupt git refs occasionally.** `-Take` powers the VM off
  hard by design. A broken `ORIG_HEAD` showed up once; deleting the file fixes
  it, and `git fsck` confirmed no other damage. The guest clone is disposable.
- **Defender's real-time protection and behaviour monitoring are off** in the
  baseline, and have been for every run. Checked on 05 Aug while investigating
  whether Defender was killing a payload — it was not.
- **Two guest settings are load-bearing and neither is a default.** Sysmon
  Event 25 (`ProcessTampering`) is commented out in SwiftOnSecurity's config,
  and Windows Error Reporting writes no memory image unless `LocalDumps` is
  configured. Without the first, process hollowing is invisible; without the
  second, a process that crashes leaves metadata and nothing else.
  `bootstrap_tools.ps1` now applies both, so a rebuilt VM comes up correct —
  before that they lived only in the baseline snapshot, and re-running the
  bootstrap would have silently reverted them.
- **A wedged VirtualBox session needs VBoxSVC restarted, and that takes every
  other VM with it.** VBoxManage returns when a state change is *queued*, not
  done. Issuing anything while the VM is in a transient state —
  `restoringsnapshot` is the usual one — can leave it stuck there with no
  process behind it, and no VBoxManage command clears it: `startvm` returns a
  bare `E_FAIL`. The way out is to save or stop every other running VM, close
  the Manager window, then `Stop-Process -Name VBoxSVC -Force`; it respawns on
  the next VBoxManage call and disk images are untouched. `vm_snapshot.ps1` now
  waits for the state to settle before each step, so the script no longer
  causes this — but a manual VBoxManage command still can.

---

## Known gaps, ranked

### 1. Dropped files have never fired — and the reason turned out to be a bug

**Persistence is closed.** Remcos `aa4d6427…` fired `persistence_installed`
**strong** on 06 Aug with two Run keys. That leaves dropped files.

Its `0` was never a property of the samples. The Remcos run dropped a PE to
`%APPDATA%\Roaming\Config\smng.exe` and the pipeline discarded every one of the
11,636 file writes Procmon recorded, because the user-writable path markers
could not match any real path. Fixed on 06 Aug; **unproven until a re-run** —
the same sample is the cheapest way to prove it, and the case data is already
recorded below.

The historical text below stands as the reasoning that led here. They may work. So might the
analyzer-attribution filter have, until a sample proved otherwise — that bug
had been silently costing findings on **every run**, and was only found because
a sample exercised it.

Two of the original four came off this list on 05 Aug:

- **PowerShell script blocks.** The loader spawned `powershell.exe` with
  `Add-MpPreference -ExclusionPath <its own path>`: 12 blocks captured, 1
  suspicious, behaviour `Defender modification`, mapped to `T1562.001`.
- **Process injection**, via a route that did not exist before — see gap 2.

Neither of the remaining two is going to be exercised by the loader sample,
because its chain dies before it reaches them. **What is needed is a family
that completes.** The guest is contained, so a downloader stalls at its first
fetch and its dropped-file path stays cold; pick something that carries
everything it needs and writes to `%APPDATA%` plus a Run key before any C2
contact.

**A sample has been selected and not yet run** — Remcos `aa4d6427…`, which
drops a PE to `%APPDATA%\Config\` and writes two Run keys. See *Remcos,
selected but not yet run*, which records what each gap should get out of it
before the fact.

### 2. Injection detection had a hole the shape of the commonest technique

Sysmon Event 8 is `CreateRemoteThread`, and process hollowing does not raise it
— `NtUnmapViewOfSection`, `WriteProcessMemory` and `SetThreadContext` raise
nothing. So `injection_events: 0` was partly a statement about the detector
rather than about the samples.

Two detectors were added rather than one, and it is as well:

- Sysmon **Event 25** (`ProcessTampering`), the purpose-built hollowing event,
  now enabled by `bootstrap_tools.ps1`. **It did not fire** on the 05 Aug run
  despite being enabled and confirmed active in the live config, so it does not
  catch this technique.
- **Application Error 1000 with a faulting module of `unknown`**, meaning the
  fault address belongs to no loaded image. This one carried the finding alone.

**`unknown` is weaker than it looks.** JIT-compiled code also lives in private
allocations with no module mapped, so an ordinary .NET application faulting in
its own JITted code produces the same record. The 05 Aug fault was at
`0x011b2c7c`, outside the 57 KB payload image carved from the dump, so it may
well have been JITted code from the injected assembly rather than the assembly
itself. The category is therefore `present` for any such crash and `strong`
only when the process is one loaders hollow — `RegSvcs`, `RegAsm`,
`InstallUtil`, `MSBuild` and friends. Nothing legitimate starts `RegSvcs.exe`
and has it fault in anonymous memory.

### 3. The spawn-triggered dump fires too early — re-dump added, unproven

The watcher dumps a new descendant the moment it appears, which is before
hollowing completes. Across three runs, every `RegSvcs` image is ~15 MB of
empty shell, and the payload was only ever captured by the crash dump — an
artifact that exists only because that payload happened to crash.

Fixed offsets cannot cover this: observed dormancy was +20s, +24s and +42s for
the same binary, so an offset tuned to one run misses the next.

**A second dump per child now fires at spawn + 10s**, measured from that
child's own first sighting rather than from launch, which is what makes it a
property of the technique instead of of the sample's dormancy. Trigger
`spawn-redump`, filename suffix `_redump`, `memory_dump_spawn_redump_seconds`
in the run summary, and a spinbox next to Max processes in the GUI. `0` turns
it off.

The pairing is the point: the spawn dump is the child before the loader touched
it and the re-dump is the same PID after, so a payload is visible as a
difference between two images rather than having to be recognised in one.

Three things to check on the first run that uses it:

- **10s is an estimate, not a measurement.** Hollowing completes in well under
  a second, so anything past ~1s has the payload; the pressure the other way is
  that a faulting payload takes the process with it. If the skipped list says
  `exited before its +10s re-dump`, lower it.
- **The process cap went 12 → 20**, because the cap counts dumps rather than
  processes and re-dumps are taken last — a cap that binds drops precisely the
  image this exists to collect.
- **A re-dump still owed when the watcher stops is recorded**, and the reason
  distinguishes the two cases: `exited before` means the delay wants lowering,
  `observation ended before` means the window was too short and the process may
  still have been holding the payload at teardown.

### 4. No anti-analysis detection

Nothing reports "the sample checked for a VM and left". The loader sample is
the case that wants it: deterministic failure at the same point across three
runs, and a deliberate bail looks identical to a broken payload from outside.

`WerFault.exe -u -p <pid>` naming a sample descendant is in `spawned_processes`
and unused; "a descendant of the sample crashed" is a cheap note with real
value, now that the crash itself is being parsed anyway.

### 5. Dumps are raw images — carver added, unproven on a sample

Carving the .NET assembly out of the crash dump on 05 Aug was done by hand:
find `MZ` headers, check `e_lfanew`, compare the timestamp against the host
image's. It took one small script and produced the single most informative
artifact of the whole investigation.

**`dynamic_analysis/pe_carve.py` now does it in the pipeline.** Every dump the
YARA pass scans is also searched structurally, and the images that no module
covers are written to `memory\carved\` as `.bin_` files — deliberately not an
extension a double-click runs.

The module list is what makes it precise. A minidump carries the process's own
loader data, so "a PE at an address no module covers" is answered from the
process's own record rather than by a heuristic. Four classifications, one of
which is evidence:

| | |
|---|---|
| `unmapped` | No module covers it and it carries code. **The finding.** |
| `resource_only` | Unmapped, no code. Fires constantly — see below. |
| `inside_module` | A second PE inside a module's range. Reported, not scored. |
| `at_module_base` | An ordinary loaded module. Counted and ignored. |

It feeds `process_injection` rather than adding a category. A hollow produces
the crash and the foreign image from one event, and a category that fires twice
for one behaviour is the volume-driven model the score design exists to avoid.
`strong` when the host is a binary loaders hollow, the same test the crash
evidence uses. **Its value is that it does not need the payload to crash** —
Event 25 is silent on this technique and the crash route only fires on a fault,
so a loader that hollows and runs cleanly was invisible to both.

**The false-positive class, found by running it against a real minidump.** An
idle Python process reported eleven unmapped PE images. All eleven were real:
two sections, `.rdata` and `.rsrc`, no code — MUI resource files, which Windows
maps with `LOAD_LIBRARY_AS_DATAFILE` and therefore never registers with the
loader. Not a parser bug; the images are genuinely there and genuinely
unmapped. It is a claim problem, and the same one as the analyzer-attribution
bug in reverse: **a signal that fires on every process on the machine says
nothing about any of them.** So the test is narrowed from "a PE" to "a PE that
could execute" — `SizeOfCode`, an entry point, or a section marked executable.
The count of what was set aside is kept and shown in the report.

The synthetic dumps in the test suite could never have shown this. They contain
only what the test author thought to put in them, which is the argument for
checking a new parser against something the operating system wrote.

**What it cannot do.** The classic overwrite-in-place hollow, where the payload
is written over the host image at its original base, classifies as
`at_module_base` and is invisible: the module list is read from the same memory
the payload now occupies, so there is nothing left to compare against. The
05 Aug sample mapped its payload *alongside* the real image, which is what made
it visible. This widens injection detection; it does not close it.

### Smaller

- `WerFault.exe` counts as sample lineage for network attribution, correctly
  (the sample caused the crash) but misleadingly: Windows Error Reporting's
  `:443` is not C2. It has not mattered yet; it would if WER used a
  non-standard port.
- `suspicious_path_hits` checks the *parent* process name against the noise
  list for non-process-create events, so a noise child under a non-noise parent
  can still surface there. Process creates were fixed; other event types were
  not reviewed.
- `background_network_processes` and the missed-descendant reconciliation are
  both exercised now — the latter recorded 3 on the 05 Aug run, where the
  sample spawned three `RegSvcs` within 15 ms and two lived less than one poll
  interval.

---

## What is proven, and what is not

The failure mode this table exists for: a feature exercised only by its own
fixtures agrees with the assumptions it was written under. The
analyzer-attribution bug is the standing proof that those can be wrong on every
run for a long time without showing.

| Feature | Status |
|---|---|
| Corroboration scoring | **Proven** on two real samples — 35 / Needs Review, then 70 / Elevated Attention after the injection signal landed |
| Network attribution | **Proven.** `other_process_requests: 3` against the sample's own four processes, on a run where Windows was busy |
| PowerShell lineage filter | **Proven.** `blocks_from_sample: 12`, `other_process_blocks_excluded: 0` — the sample's own block survived, so the filter is not too tight |
| `activity_observed` | **Proven.** `false` before the fix and `true` after, on the identical sample and chain |
| Crash-as-injection | **Proven.** Fired on the hollowed `RegSvcs`, and moved the verdict a band |
| Crash-dump collection | **Proven**, and produced the payload |
| Adaptive window | **Fired, on the wrong case** — see below |
| Received-file collection | **Root resolution proven**; `received_files.roots` named the real `tools\fakenet\defaultFiles`. The *collection* path is still unproven — nothing has been uploaded since it was written |
| Containment refusal | **Unproven.** Written after a detonation got through while armed; nobody has tried to run armed since |
| Spawn re-dump | **Proven.** Fired at t11 on a child first seen at t1, on live Remcos. Revealed nothing new *for that sample*, which drops rather than hollows |
| PE carve | **Runs clean on real dumps** — 43 modules, 0 rejected, 0 false positives across five ProcDump images of live malware. Its finding path is still unproven: no run has yet produced an unmapped image |
| File writes / dropped files | **Fixed twice, unproven.** The first fix was incomplete — `dropped_file_triage`'s own markers were dead too, so candidates would still have been 0. Needs a clean-baseline re-run |
| `external_contact` on a bare IP | **Fixed, unproven.** Never fired for an IP-only C2; replaying the Remcos inputs now scores it strong |
| Sysmon Event 25 | **Enabled and silent.** Does not catch this technique; may catch others |

Still worth disbelieving: the adaptive window needs the memory dump watcher for
its activity probe. A run that is not elevated has no probe and the window
silently stays fixed — recorded as `adaptive_available: false`, which is the
field to check rather than assuming extension was available.

### The adaptive window is more expensive than it looks

The UPX control fired it: `mimikatz.upx.exe` sits at its interactive prompt, so
it is alive and childless forever, which the probe cannot tell from a crypter
asleep. 14 extensions, `extension_cap_reached` at 600s.

That run took **1148 seconds** against 271 and 282 for the two 180s runs before
it. Only 600 of that is the window; teardown was 548, because Procmon captured
**113,367 events** against ~41–50k, and all of them get parsed.

The time is the smaller cost. **Some of the pipeline's attribution is bounded
by the window rather than by lineage, and lengthening the window is free for the
first kind and corrosive to the second:** Windows scheduled maintenance fired
four minutes in and put seven LOLBins into the sample's Spawned Processes, and
Windows Troubleshooting ran PowerShell, raising a false `scripted_execution`
category. The second of those is fixed; the first is correct policy and simply
noisier on a long run.

Both control READMEs now say to untick *Extend if dormant* — neither sample can
benefit and both are resident by construction. The probe still cannot tell
"waiting at a prompt" from "asleep before unpacking", and there is no cheap
signal that does: both are alive, quiet and childless.

**The cap stays at 600s.** It was briefly dropped to 300 and put back, because
lowering it is the wrong lever: the cap is *total* observation, not extra, so
300 buys four extension steps and cannot outlast the five-minute sleep the
feature exists for. It penalises the samples this is meant to catch without
helping the resident case at all.

After the PowerShell fix, the only *scored* input that still scales with window
length is the persistence diff, and it held clean across a ten-minute run with a
full round of Windows idle maintenance in it. LOLBin counts and Procmon volume
feed only the context score, which is capped at 15, so they degrade the report
rather than the verdict.

---

## Conventions worth keeping

These are why this session's bugs were findable, and they are load-bearing.

**Silence must be distinguishable from absence.** Every filter that removes
something records that it did: `analyzer_events_excluded`,
`os_baseline_events_excluded`, `noise_dns_excluded`, `background_processes`,
`missed_descendants`, `other_process_blocks_excluded`, `skipped` dumps with
reasons. A report that says nothing happened and a report that could not tell
must never look alike.

**Attribute by lineage or by requesting process, never by maintaining a list of
everything else.** Name lists exist only as suppression aids that run *before*
attribution. This rule was broken three times in one day — network evidence,
PowerShell blocks, and the process-name set feeding network attribution — and
each break looked correct until a run made it visible.

**A control that only writes to a log is documentation.** The containment check
emitted `CONTAINMENT WARNING` and launched the sample anyway. Test your controls
deliberately; the armed detonation that exposed this was a test, and it is the
only reason it was found.

**Check the behaviour, not the text.** A config file containing
`ProcessTampering` in a comment satisfied a text search while the live config
had it disabled. `sysmon64.exe -c` dumping the running configuration is the real
test, and the same shape of mistake appeared three times on 05 Aug.

**A control's contract is directional.** The UPX control says "anything less
means the dump or the delta logic is at fault." More is fine.

**A substring list is not a regex, and nothing will tell you.** 46 markers
across four modules were written with regex-style doubled separators and matched
with a plain `in` test, so they matched nothing for the life of the project. It
cost every file write and every file create on every run, and 332 tests passed
over it, because no test ever asserted a real path against them. When a detector
is a list of literals, test it with a string that must match — not with the
constants, which are the thing that is wrong. And when one instance turns up,
**sweep for the rest**: the first fix here was incomplete and would have looked
like a failed re-run rather than a partial fix.

**Repair a suppression list in the same change as the detector it guards.**
Every module with dead detection markers had dead exclusion markers too. A live
detector against a dead exclusion list is worse than both being dead, because
the analyzer writes thousands of files into the directory it is watching.

**A signal that fires on everything says nothing about anything.** The PE carver
reported eleven unmapped images in an idle Python process, all of them real and
all of them Windows resource files. Correctness was never the problem; the claim
was. Before trusting a new detector, run it against something known-clean — and
if it is a parser, against a file the operating system wrote rather than one
this repository built, because a synthetic fixture only contains what its author
already thought of.

**Commit messages carry the evidence.** Every fix names the run that exposed it
and the numbers involved. `git log` is the incident record.

---

## Reading a run

Order to check things in, learned the hard way:

1. **`network_isolation.level`** from the run summary. `ok` now means contained;
   `uncontained` blocks the run outright. The GUI's line is re-read immediately
   before each launch, so it should agree — but the summary is the authority.
2. **Warnings first.** Degraded Collection, Cannot Be Reached, Name Resolution
   Was Not Served, Observation May Be Incomplete. Each one means part of the
   run is unobserved rather than quiet.
3. **`Capture` column** on the dumps. `Live (smeared)` qualifies every YARA
   result from that image. A PID appearing twice, once `process-spawn` and once
   `spawn-redump`, is a before/after pair — a size jump between them is a
   payload being written in.
4. **Evidence Behind The Verdict.** Which categories fired and which were judged
   strong. The score is descriptive; this is the reasoning.
5. **Crashes In The Sample's Tree.** A fault outside any mapped module is
   injection evidence, and often the only record of hollowing.
6. **Executables The Loader Never Mapped.** Structural, so it works where a
   signature does not: the 05 Aug payload matched no rule in the set and was
   conclusive from its headers. Read the two timestamps side by side — an image
   years newer than the process hosting it did not ship with it.
7. **Memory-only rules.** The actual finding on a packed sample — but an
   obfuscated payload can be present and match nothing, which is exactly the
   case the row above covers.
7. **Spawned vs Background processes.** The first is the sample; the second is
   Windows.
8. **Files Received By The Simulated Internet**, and `memory\crash_dumps\`. If
   either is non-empty, that is the run's best artifact — export before
   reverting.

---

## AgentTesla reference data

The fully-worked case. Any regression shows up as a change here.

| | |
|---|---|
| SHA256 | `31a762fdce1008e635a5e6486d7bc50b4bce671c9232006216e70cd8f2a4a7fb` |
| C2 | `ftp.cyberflor.co` |
| FTP credential | `michi@cyberflor.co` |
| Memory-only rules | `Windows_Trojan_AgentTesla_d3ac2b2f`, `Windows_Trojan_AgentTesla_ebf431a8`, `Windows_Generic_Threat_808f680e` |
| Exfil shape | FTP control `:21`, passive data `:60000-60010` |
| Report format | `Time:/User Name:/Computer Name:/OSFullName:/CPU:/RAM:` then `Host:/Username:/Password:/Application:` blocks split by `<hr>` |
| Score | 85 · Likely Malicious / High, replayed from the real summary |

Expected on a clean run: 4 dumps all `Frozen`, scheduled offsets matching 0
rules, spawn and exit dumps matching 3, `network_events: 2`, and
`ftp.cyberflor.co` alone in the requested-domains card.

The report format is itself a durable signature — a YARA rule could be written
against a captured upload rather than against the binary. The 03 Aug upload was
recovered by hand from `tools/fakenet/defaultFiles/FakeNet.html` before the
baseline was rebuilt, and is the reference artifact for that format.

---

## Loader reference data (`422e30ed…`)

Labelled Formbook by MalwareBazaar. **That attribution is unverified** — no
artifact from any run names a family.

| | |
|---|---|
| SHA256 | `422e30edd409936c649905ba4a8f58ed533287da77965268342ec38221d28231` |
| Chain | sample → `powershell.exe Add-MpPreference -ExclusionPath <self>` → 3× `RegSvcs.exe` within 15 ms |
| Outcome | one `RegSvcs` faults `0xc0000005` in unmapped memory; the others die inside one poll interval |
| Dormancy | +20s, +24s, +42s across three runs |
| Score | 70 · Elevated Attention / High — `process_injection` (strong) + `scripted_execution` |
| Payload | x86 .NET EXE, 57,344 bytes, compiled 2025-06-18, at dump offset `0x4a6a7` |

**The payload was recovered on 05 Aug**, from the WER crash dump rather than any
scheduled dump. A foreign .NET assembly is mapped inside `RegSvcs.exe` alongside
the real image — RegSvcs's own header carries timestamp `0x5ff2b99b`, matching
what the Application Error reported, and the second carries a 2025 one. **That
is process hollowing confirmed by the PE headers, independently of any
detector.**

**It has no plaintext indicators at all.** 428 strings in the payload region:
no URLs, no domains, no IPs, no credential or wallet paths, no persistence
strings, no family markers. An obfuscated stage-2 with its config in a
2,380-byte `.rsrc` blob. That is why YARA matched nothing across nine images
while the UPX control passes — there is nothing for a signature to key on, and
the ruleset is not at fault.

**This explains three runs of empty findings.** The chain dies at stage 2: the
loader hollows `RegSvcs`, stage-2 starts, and it faults before decrypting stage
3. There was never going to be a C2 connection, a Run key or a dropped file.
Persistence and dropped-files sitting at `0` for this sample is a property of
the sample, not a gap in the pipeline.

**The crash is deterministic** — same chain, same failure point, three runs. Not
flaky hollowing, and not Defender, which has real-time protection off. What
remains is anti-analysis or a broken crypter, and the pipeline cannot currently
tell those apart (gap 4).

If you return to this sample, the `.rsrc` blob is where the config lives and
that is a static-analysis job on the carved image, not another detonation.

---

## Remcos reference data (`aa4d6427…`) — run 06 Aug

Recorded as a prediction before the run, which is why it was worth running: four
of the expectations held and three failed, and every one of the three failures
was a pipeline bug rather than a property of the sample. A run described only
afterwards would have read as a clean success.

**What the run produced:** 70 · Elevated Attention / High, 2 categories agreeing
(`packed_payload`, `persistence_installed` strong). After the four fixes below,
the same inputs score **105 · Likely Malicious**, 3 present and 2 strong.

| | |
|---|---|
| SHA256 | `aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715` |
| Family | Remcos RAT — HA reports `Gen:Variant.Rescoms`, which is Bitdefender's name for Remcos |
| Source | `hybrid-analysis.com/sample/aa4d6427…/6a4d71d9e17d51fadd07ca1a` · 100/100 · AV 75% |
| Type | Native PE32. **Not .NET** — deliberately a different shape from `422e30ed` |
| Chain | sample → creates a process **suspended** → writes into it → `%APPDATA%\Config\smng.exe` |
| Injection | `CreateProcess` suspended + write to remote process + `Set`/`GetThreadContext` |
| Dropped | `%APPDATA%\Config\smng.exe`, 18/24 vendors |
| Persistence | `HKCU\…\CurrentVersion\Run` **and** `HKLM\SOFTWARE\WOW6432Node\…\CurrentVersion\Run`, value `TRY150-6P1GV6` |
| C2 | `62.60.226.68:24042` |
| Other lookup | `pro.ip-api.com` (geolocation, `https://pro.ip-api.com/line/?key=…`) |
| IDS | `ET MALWARE Remcos 3.x Unencrypted Checkin/Server Response` |
| Outcome | No `WerFault` child. It completes — which is why it was chosen |

### Prediction against outcome

| Predicted | Outcome |
|---|---|
| Run keys in HKCU and HKLM\Wow6432Node, value `TRY150-6P1GV6` | **Exact.** Both, same value, same target |
| `persistence_installed` strong | **Held.** First time this category has fired on any run |
| Drop to `%APPDATA%\Config\smng.exe` | **The file was written; the pipeline did not see it.** Bug 1 |
| C2 `62.60.226.68:24042` | **Exact.** Attributed to `smng.exe` by the diverter |
| `external_contact` strong | **Failed.** Attribution worked and the category still did not fire. Bug 2 |
| Spawn re-dump catches `smng.exe` populated | **Fired at t11**, child first seen t1 — feature works |
| Carver reports `present`, not `strong` | **Reported 0.** Correct: see below |
| `sysmon_injection_events: 0` | **Held**, as designed |

**The re-dump worked but had nothing to reveal.** All five dumps matched the same
three Remcos rules, because `smng.exe` was already Remcos at t1 — this sample
drops and executes rather than hollowing. Whatever it wrote into the suspended
child was configuration, not an image, which is also why the carver's 0 is
correct rather than a miss.

**The carver's first run on real dumps was clean**: 43 modules, 250–274 regions
per image, `rejected: 0`, `resource_only: 0`, no false positives on live
malware.

### Four bugs this run exposed, all fixed

1. **46 path markers across four modules had never matched anything.** They are
   compared with a plain `in` test but were written regex-style — `r"\users\\"`
   is a literal *double* backslash, which appears in no Windows path. See
   *The dead-marker bug* below; it is the largest single defect found so far.
2. **`external_contact` could not fire for an IP-only C2.** `present` gated on
   `notable_domains > 0 or external_destinations > 0`. Remcos dialled a
   hard-coded IP, so there was no DNS lookup; FakeNet diverted the connection, so
   the pcap logged none. The diverter's per-process record had it,
   `sample_unusual_ports` named it exactly — and `strong` is only consulted for a
   category already `present`. A C2 contact the pipeline watched, attributed and
   flagged scored nothing, costing a whole verdict band. `unusual_ports` now
   makes the category present in its own right.
3. **The sample's own process was never dumped, and nothing said so.** The root
   has one route to being imaged — a scheduled offset coming due while it is
   alive. The spawn dump excludes it by design and the exit dump runs when it is
   already unreadable. The parent exited at ~t1 with the first offset at +5, so
   all five dumps were of the child, and `dumps_skipped` read 0. **That was the
   process that did the unpacking.** A skip is now recorded naming the offsets
   that were pending.
4. **A blank autoruns row counted as suspicious.** Two genuine Run keys were
   reported as three; the extra row had a category and a hive location and
   nothing else, and qualified purely by being "Logon" with no signer.

Also: the report's autoruns table had no **Location** column, which is why the
two genuine entries rendered as an apparent duplicate.

### The dead-marker bug

Found by fixing the first instance and then sweeping for the rest. **46 markers
in four modules**, every one matched with a plain `in` or `startswith` test and
every one written with a doubled separator that no real path contains:

| Module | What was dead |
|---|---|
| `procmon_parser` | user-writable roots, the noise list, `\currentcontrolset\services\` |
| `dropped_file_triage` | **all five** suspicious locations, **all seven** exclusions, all six analyzer-noise markers |
| `diff_tasks`, `diff_services` | all five suspicious-path hints in each |
| `findings` | services and drivers markers, and both copies of the analyzer case-path suppression |

**`dropped_file_triage` is the one that mattered most.**
`collect_dropped_file_candidates` discards any candidate whose path is not in a
suspicious location, so with that list dead `total_candidates` was pinned at 0
*structurally*. Fixing the Procmon side alone would not have moved it — the
Remcos drop would have reached that function and been thrown away there instead.
The first fix was incomplete and would have looked like a failed re-run.

Each module needed its suppression list repaired in the same change as its
detection list. A live detector against a dead exclusion list is worse than
both being dead: `\cases\` suppression exists precisely because the analyzer
writes thousands of files into the directory it is watching.

**A guard test now scans every module in the package** for short path-shaped
literals containing a doubled backslash and fails on any of them. That is the
part worth keeping — the instances are fixed, but the class of bug is invisible
to review and survived 332 tests.

One consequence to watch: repairing `\currentcontrolset\services\` on the
general list took `registry_create` from 5 interesting events to **140** in a
run where the sample did nothing, purely from Windows service-key churn. It is
now on a separate value-writes-only list, so setting `ImagePath` fires and
creating a service key does not.

### The 03:22 re-run was void — revert the VM first

The second run of this sample tested nothing, because the guest was not reverted.
Remcos was **already installed and still running**: `smng.exe` appears in
FakeNet's table at PID 10756, the identical PID from the 02:54 run, still
beaconing to `62.60.226.68:24042`, and `autoruns before_total: 1605` is exactly
the previous run's `after_total`. The sample found its own installation and
exited with code 2 — one process create, no spawn, no new autorun entries.

Two things that run did establish. The root-never-dumped skip fired verbatim,
naming `+2s, +25s`, and it is the only reason the run was diagnosable at all.
And lineage attribution handled the contamination correctly: `smng.exe` was
counted as a *background* process rather than the sample's, so its very real C2
traffic was not scored — which was right, because it was not this run's.

**Revert to the clean snapshot before re-running.** A sample that installs
persistence is not idempotent, and a dirty baseline turns a detonation into a
no-op that reads like a clean result.

### Why this one, after two rejections

Recorded so the next session does not re-tread it. Two MalwareBazaar samples
labelled Formbook were rejected on their sandbox reports before any run:

- `d712b6f9…` — 1 MB .NET crypter, an unnamed 931,963-byte `.rsrc` resource at
  entropy 7.99, so the payload is embedded rather than fetched. FileScan's
  report is **static with emulation only** (`success_partial`), so it has no
  process tree, no registry and no network to judge; it never names a family
  either. Its similarity search claims 1.0 to a non-.NET Sality sample, which is
  not credible. Still a live candidate for gap 3 — vxCube reports
  *"unauthorized injection to a recently created process"* — but unproven.
- `1cf5d1800…` — Triage `260608-lr276sbx8p`. Scored 10/10 on both Win10-2004
  and Win11-21H2 and **crashed on both**: the only children are `WerFault.exe`,
  both targeting the sample's own PID, with a `Program crash` signature and no
  injection, persistence or network. A shorter chain than `422e30ed`, which at
  least reached three `RegSvcs`.

**The lesson is a selection rule.** A 10/10 score with a two-node process tree
ending in `WerFault` is a crash, not a compromise — the score came from family
identification and a payload memory hit, not from a completed chain. Read the
process tree before the score: reject when the only child is `WerFault.exe`,
take when a real child appears alongside an autostart or `SetThreadContext`
signature. Note also that Triage, with a mature Formbook config extractor, still
produced an empty **Malware Config** panel for that sample — roughly where this
pipeline's memory YARA landed on `422e30ed`.
