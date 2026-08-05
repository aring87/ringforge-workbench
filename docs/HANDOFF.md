# Handoff

State of the work, for picking up in a fresh session. `docs/WORKFLOW.md` is the
run procedure; this is what is done, what is known-broken, and what is worth
doing next.

**Last updated:** 2026-08-04 · `main` at `v1.10.0`

> **Since v1.10.0:** gaps 2, 3 and 4 below have been implemented and are
> covered by unit tests. **None of the three has run against live malware.**
> They are written, not proven — see *What is implemented but unproven*.

---

## Where things stand

The dynamic analysis pipeline was validated end to end against a live
AgentTesla sample (`31a762fdce1008e635a5e6486d7bc50b4bce671c9232006216e70cd8f2a4a7fb`).
A single run captured dormancy, self-spawn, unpack, C2 resolution, FTP
authentication and the upload of its stolen-data report.

Both controls pass:

| Control | Result |
|---|---|
| `test_specs/memory_canary/` | Exactly one memory-only rule, both dumps `Frozen` |
| `test_specs/upx_control/` | 5 memory-only rules against a predicted 4 — see below |

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

---

## Known gaps, ranked

### 1. Three code paths have never fired on real malware

**PowerShell script blocks now have.** A Formbook sample
(`422e30edd409936c649905ba4a8f58ed533287da77965268342ec38221d28231`, run
2026-08-05) spawned `powershell.exe` with
`Add-MpPreference -ExclusionPath <its own path>`: 12 blocks captured, 1
suspicious, behaviour `Defender modification`, mapped to `T1562.001`. That path
had been `0` on every run ever performed. It works.

Persistence hits, dropped files and process injection are still `0` on every
run. They may work. So might the analyzer-attribution filter have, until a
sample proved otherwise — that bug had been silently costing findings on
**every run ever performed**, and was only found because a sample exercised it.

The Formbook run did not reach them: it spawned `RegSvcs.exe`, the .NET
hollowing target, and `RegSvcs` faulted (two `WerFault.exe -u -p 1404`, plus a
second `RegSvcs` that exited before it could be dumped). No payload ever
materialised — 0 YARA matches across 6 dumps. Failed hollowing, or a sample
that recognised the guest and bailed; the pipeline cannot currently tell those
apart.

`samples/74eb42416b47c082fc867764b577ceac6f1bd68e192695d79a9e48a7bd3fdd69.zip`
is unanalyzed. A family that drops a payload, installs persistence or injects
would exercise those paths the way AgentTesla exercised the memory and network
ones. **This is the highest-value next step.**

For a sample chosen deliberately rather than whatever is to hand: the guest is
contained, so a downloader stalls at its first fetch and its dropped-file path
stays cold. Pick a family that carries everything it needs — Formbook/XLoader
or Remcos both hollow a legitimate process, write a copy to `%APPDATA%` and add
a Run key, all before any C2 contact. PowerShell script blocks need their own
sample; no PE family reliably produces them, so a `.ps1` or an LNK/HTA loader
that shells out to `powershell -enc` is the way to reach that path.

### 2. The score does not discriminate — *implemented, unproven*

| Sample | Was | Now (from unit fixtures) |
|---|---|---|
| Memory canary (benign) | 24 · Needs Review / Medium | 33 · **Needs Review / Medium** |
| mimikatz (packed) | 69 · Needs Review / Medium | 50 · **Elevated Attention / High** |
| AgentTesla (live) | 60 · Needs Review / Medium | 85 · **Likely Malicious / High** |

The AgentTesla row is **replayed from the real 03 Aug
`dynamic_run_summary.json`**, not reconstructed. The other two are fixtures.

`High` required `>120` and nothing reached it, because almost every term in the
sum was individually capped. The model is now `dynamic-corroboration-v3`: the
verdict comes from how many independent evidence categories agree, and activity
volume is capped at 15 points so noise cannot move a band.

The canary staying at Medium is deliberate and is the control's contract. One
kind of evidence with nothing corroborating it is a single unexplained
observation, which is exactly what that sample is built to produce.

Replaying the real summary is what caught the first version reading host-wide
telemetry: FakeNet's log held ten domains, nine of them Windows' own, while
OneDrive, M365Copilot and three msedgewebview2 processes connected during the
window. All nine classified as baseline, so the count was right **by luck** —
one non-baseline lookup from any of those processes would have scored as the
sample's C2 contact. Network evidence is now attributed before it is scored:
domains from Sysmon, connections from FakeNet's diverter, which names the
requesting process.

The same replay showed the pcap is the wrong source for unusual ports. It
recorded `0` on the run where the sample used the passive FTP port `:60009`;
the diverter had it. `score_detail.network_attribution` records what was
attributed to the sample and what the host did anyway.

### 3. FakeNet's received files are discarded — *implemented, unproven*

AgentTesla's exfil report was written to
`tools/fakenet/defaultFiles/FakeNet.html` — it overwrote FakeNet's own default
page — and was found by hand.

Listener roots are now read from the FakeNet config and snapshotted before
launch, and anything new *or modified* is copied into `network\received\` in the
case directory, hashed, and listed in the report. Copied, never moved.

Unproven in the way that matters: no sample has uploaded anything since. The
snapshot-and-diff is exercised by tests against a synthetic FakeNet install, but
whether the real FTP listener's root resolves the way `listener_roots()` expects
has not been confirmed against the actual `tools/fakenet/` layout in the guest.
**Check `network\received\` on the next run that shows an upload.**

### 4. The observation window is fixed against variable dormancy — *implemented, unproven*

180 seconds, while the same binary sat dormant for 21, 37, 38, 41, 44 and 83
seconds across six runs.

The window now extends in 30-second steps, to a 600-second cap, while the sample
is still running and the dump watcher has not seen it spawn anything. Reaching
the cap while still silent raises **Observation May Be Incomplete** in the
report, which is the half that closes the original gap: a crypter sleeping five
minutes no longer produces a clean-looking report.

The extension path has never fired — every recorded run had the sample act well
inside 180 seconds. A sample that genuinely sleeps past the window is what would
exercise it.

### 5. PowerShell script blocks were attributed by time, not by lineage — *fixed*

`collect_scriptblocks` takes every block in the Sysmon window and calls it the
sample's unless it is analyzer activity. A mimikatz control run — a sample that
spawned **nothing**, `processes_observed: 1` — reported `blocks_from_sample: 24`
and one suspicious block, because Windows Troubleshooting ran
`C:\WINDOWS\TEMP\SDIAG_*\TS_DiagnosticHistory.ps1` during the window. That
raised a `scripted_execution` evidence category for behaviour the sample had no
part in.

The verdict survived by luck: `packed_payload` was already strong, and one
strong category reaches High on its own. It will not always survive.

Same class as the network-attribution bug in `1f73560`. Blocks are now filtered
to the sample's tree, resolved from Sysmon's ProcessCreate records via
`sample_descendant_pids`. Two details worth knowing:

- 4104 carries **no EventData ProcessId**. The executing PID is an attribute of
  the System block's `Execution` element, so the XML parser had to expose it —
  `execution_process_id`, deliberately separate from `process_id`, which for
  Sysmon means the process an event is *about* rather than the one that emitted
  it.
- Script blocks are now collected **after** Sysmon rather than before, because
  the lineage they are filtered against comes from Sysmon.

Blocks from other processes are counted (`other_process_blocks_excluded`), not
dropped, and kept in a different bucket from analyzer blocks so the two stay
tellable apart. `attributed_by_lineage` records whether the filter was
available at all; when lineage cannot be resolved, everything is counted the
way the findings degrade, and the run says so.

**Unproven on a real run.** The next detonation with PowerShell activity is
what confirms it — Formbook is the obvious candidate, since its
`Add-MpPreference` block must survive the filter.

### Smaller

- No anti-analysis detection. Nothing reports "the sample checked for a VM and
  left." The Formbook run is the case that wants it: `RegSvcs.exe` faulted
  immediately after being spawned, and a deliberate bail looks identical from
  outside. **`WerFault.exe -u -p <pid>` naming a sample descendant is already in
  `spawned_processes` and unused** — "a descendant of the sample crashed" is a
  cheap note with real value.
- `WerFault.exe` counts as sample lineage for network attribution, correctly
  (the sample caused the crash) but misleadingly: Windows Error Reporting's
  `:443` is not C2. It did not matter on the Formbook run; it would if WER ever
  used a non-standard port.
- Dumps are full 100–160 MB images with no payload reconstruction, which limits
  what can be done with them downstream.
- Two features are correct but **unexercised in the case they exist for**: the
  missed-descendant reconciliation needs a run where the double-spawn recurs
  (it happened in 2 of 6), and `background_network_processes` needs a
  connecting process the noise filter does not already catch. Both correctly
  reported nothing on clean runs.

---

## What is implemented but unproven

Everything in this section has unit tests and has never run against a live
sample. Listed together because the failure mode is shared: a feature that is
only exercised by its own fixtures agrees with the assumptions it was written
under, and the analyzer-attribution bug is the standing proof that those can be
wrong on every run for a long time without showing.

| Feature | Status after the Formbook run |
|---|---|
| Received-file collection | **Root resolution proven.** `received_files.roots` named the real `tools\fakenet\defaultFiles`, so `listener_roots()` matches the actual install. The *collection* path is still unproven — nothing was uploaded |
| Adaptive window | **Fired, and it is too expensive.** See below |
| Corroboration scoring | **Ran on a second real sample.** Landed at 35 / Needs Review on one category, which is the honest reading of a sample that crashed before doing anything else |
| Network attribution | **Working.** `other_process_requests: 11` against 1 sample destination on a run where Windows was busy |

Two features came off the unexercised list in the same run:
`missed_descendants` recorded 1 (a `WerFault` Sysmon saw and the dump watcher
missed), and `background_network_processes` populated with four processes.

Still worth disbelieving: the adaptive window needs the memory dump watcher for
its activity probe. A run that is not elevated has no probe and the window
silently stays fixed — recorded as `adaptive_available: false`, which is the
field to check rather than assuming extension was available.

### The adaptive window is more expensive than it looks

The UPX control fired it: `mimikatz.upx.exe` sits at its interactive prompt, so
it is alive and childless forever, which the probe cannot tell from a crypter
asleep. 14 extensions, `extension_cap_reached` at 600s.

The run took **1148 seconds** against 271 and 282 for the two 180s runs before
it. Only 600 of that is the window; teardown was 548, because Procmon captured
**113,367 events** against ~41–50k, and all of them get parsed. Longer window,
more events, longer parse.

The time is the smaller cost. **The pipeline's attribution is half
lineage-based and half window-based, and lengthening the window is free for the
first and corrosive to the second:**

- Windows scheduled maintenance fired four minutes in, putting seven LOLBins
  (`hpatchmonTask.cmd`, `reg query …\HotPatch`, `rundll32 Startupscan.dll`) into
  the sample's Spawned Processes. Correct policy — a LOLBin is a finding
  whoever started it — but they are only there because the run was long.
- Windows Troubleshooting ran PowerShell, raising a false
  `scripted_execution` category. See gap 5.

Both control READMEs now say to untick *Extend if dormant* — neither sample can
benefit, and both are resident by construction. The probe still cannot tell
"waiting at a prompt" from "asleep before unpacking", and there is no cheap
signal that does: both are alive, quiet and childless. Turning it off where the
answer is known in advance is the whole mitigation.

**The cap stays at 600s.** It was briefly dropped to 300 and put back, because
lowering it is the wrong lever: the cap is *total* observation, not extra, so
300 buys four extension steps and cannot outlast the five-minute sleep the
feature exists for. It penalises the real samples this is meant to catch
without helping the resident case at all — a resident sample still runs to
whatever the cap is.

After the PowerShell fix above, the only *scored* input that still scales with
window length is the persistence diff, and it held clean across a ten-minute
run with a full round of Windows idle maintenance in it. LOLBin counts and
Procmon volume feed only the context score, which is capped at 15, so they
degrade the report rather than the verdict.

---

## Conventions worth keeping

These are why the session's bugs were findable, and they are load-bearing.

**Silence must be distinguishable from absence.** Every filter that removes
something records that it did: `analyzer_events_excluded`,
`os_baseline_events_excluded`, `noise_dns_excluded`, `background_processes`,
`missed_descendants`, `skipped` dumps with reasons. A report that says nothing
happened and a report that could not tell must never look alike.

**Attribute by lineage or by requesting process, never by maintaining a list of
everything else.** Name lists exist only as suppression aids that run *before*
attribution. Two runs of the same control produced entirely different background
sets; that approach does not converge.

**A control's contract is directional.** The UPX control says "anything less
means the dump or the delta logic is at fault." More is fine.

**Commit messages carry the evidence.** Every fix this session names the run
that exposed it and the numbers involved. `git log` is the incident record.

---

## Reading a run

Order to check things in, learned the hard way:

1. **`network_isolation.level`** from the run summary, never the GUI's
   containment line — the GUI can be showing a pre-arm state.
2. **Warnings first.** Degraded Collection, Cannot Be Reached, Name Resolution
   Was Not Served, Observation May Be Incomplete. Each one means part of the
   run is unobserved rather than quiet.
3. **`Capture` column** on the dumps. `Live (smeared)` qualifies every YARA
   result from that image.
4. **Memory-only rules.** The actual finding on a packed sample.
5. **Spawned vs Background processes.** The first is the sample; the second is
   Windows.
6. **Evidence Behind The Verdict.** Which categories fired, and which were
   judged strong. The score is descriptive now; this is the reasoning.
7. **Files Received By The Simulated Internet.** If it is non-empty, that is the
   run's best artifact — export `network\received\` before reverting.

`suspicious_path_hits` checks the *parent* process name against the noise list
for non-process-create events, so a noise child under a non-noise parent can
still surface there. Process creates were fixed; the other event types were not
reviewed.

---

## AgentTesla reference data

Kept because it is the only sample this pipeline has been fully validated
against, and any regression will show up as a change here.

| | |
|---|---|
| SHA256 | `31a762fdce1008e635a5e6486d7bc50b4bce671c9232006216e70cd8f2a4a7fb` |
| C2 | `ftp.cyberflor.co` |
| FTP credential | `michi@cyberflor.co` |
| Memory-only rules | `Windows_Trojan_AgentTesla_d3ac2b2f`, `Windows_Trojan_AgentTesla_ebf431a8`, `Windows_Generic_Threat_808f680e` |
| Exfil shape | FTP control `:21`, passive data `:60000-60010` |
| Report format | `Time:/User Name:/Computer Name:/OSFullName:/CPU:/RAM:` then `Host:/Username:/Password:/Application:` blocks split by `<hr>` |

The report format is itself a durable signature — a YARA rule could be written
against a captured upload rather than against the binary.

The 03 Aug exfil upload was recovered by hand from
`tools/fakenet/defaultFiles/FakeNet.html` before the baseline was rebuilt, and
is the reference artifact for that format.

---

## Formbook reference data

Kept for comparison against a run where the chain completes.

| | |
|---|---|
| SHA256 | `422e30edd409936c649905ba4a8f58ed533287da77965268342ec38221d28231` |
| Chain | sample → `powershell.exe Add-MpPreference -ExclusionPath <self>` → `RegSvcs.exe` |
| Outcome | `RegSvcs` faulted: 2× `WerFault -u -p 1404`, plus a second `RegSvcs` that exited before it could be dumped |
| Memory YARA | 0 matches across 6 dumps — the payload never unpacked |
| Score | 35 · Needs Review / Medium, on `scripted_execution` alone |
| Dormancy | PowerShell at +23s, `RegSvcs` at +24s, sample exited ~+24s |

The sample's own process was dumped **once, at +5s**, before it had spawned
anything. It exited with the +25s offset due on the same tick, which suppresses
the exit dump by design; that skip is now recorded rather than silent.

Expected on a clean run: 4 dumps all `Frozen`, scheduled offsets matching 0
rules, spawn and exit dumps matching 3, `network_events: 2`, and
`ftp.cyberflor.co` alone in the requested-domains card.
