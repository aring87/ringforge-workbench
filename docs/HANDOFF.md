# Handoff

State of the work, for picking up in a fresh session. `docs/WORKFLOW.md` is the
run procedure; this is what is done, what is known-broken, and what is worth
doing next.

**Last updated:** 2026-08-06, after the loader's eighth run (`9e69fcbc`, 21:15) —
the registry-read code was on the guest and the Procmon config was not, so the
pass proved its *guard* (a zero refused to read as an answer) and not its finding
path. That run also lost the packer image to an offset that never came due and
said nothing about it, which produced two changes: any process exiting with
offsets pending now names them, and the parent is imaged at the moment it spawns a
child — the one instant a loader is certainly holding its payload. Before that,
the seventh run (`253c1d72`, 20:23).
It was set up for gap 4's registry-read collection path and tested none of it —
the guest was a commit behind and the config field was on the default — but it
proved the chain-crashed warning live, produced the packer's before/after pair
from the `1, 25` offsets, and reported `unmapped: 0` on every `RegSvcs` image
including the full-memory crash dump, which is gap 5's own written failure
criterion. Gap 5 is revised accordingly. The commit that
last touched this file is the anchor — `git log -1 docs/HANDOFF.md` — rather
than a hash written inline, which has been stale here before.

---

## Where things stand

Three live samples have been through the pipeline end to end.

**Remcos** (`aa4d6427…`) is the current reference case and the first sample to
produce a corroborated verdict: **125 · Likely Malicious**, four categories with
two strong — persistence, dropped payload, C2 contact and a memory-only rule.
It closed gap 1 and proved the spawn re-dump. See *Remcos reference data*.

**AgentTesla** (`31a762fd…`) is the fully-worked case: dormancy, self-spawn,
unpack, C2 resolution, FTP authentication and the upload of its stolen-data
report, all captured in one run.

**A .NET loader** (`422e30ed…`, labelled Formbook by MalwareBazaar and not
otherwise attributed) has been run **seven** times. It injects into
`RegSvcs.exe` — how is now in doubt, see gap 5 — and its stage-2 payload faults
before it can decrypt stage 3, identically every time.
The pipeline recovered that payload on 06 Aug and static analysis identified it
end to end: a SmartAssembly-protected reflective loader disguised as a
sliding-puzzle game, `SmartOptimization.dll`, with no config anywhere in it —
the config is in the stage it would invoke, which the crash prevents. See
*Loader reference data*.

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

### 1. CLOSED — persistence and dropped files, 06 Aug

All four paths on this list have now fired on real malware. Kept because how it
closed is the most instructive thing in this document.

- **PowerShell script blocks** (05 Aug). The loader spawned `powershell.exe`
  with `Add-MpPreference -ExclusionPath <its own path>`: 12 blocks captured, 1
  suspicious, behaviour `Defender modification`, mapped to `T1562.001`.
- **Process injection** (05 Aug), via a route that did not exist before — gap 2.
- **Persistence** (06 Aug). Remcos `aa4d6427…` wrote `TRY150-6P1GV6` to the Run
  key in both HKCU and HKLM\Wow6432Node. `persistence_installed` **strong**.
- **Dropped files** (06 Aug). The same run dropped
  `%APPDATA%\Roaming\Config\smng.exe`, a PE, flagged by 18/24 vendors.

**The `0` was never a property of the samples.** Two of them were, and then a
detonation that should have produced both still reported nothing, because the
user-writable path markers could not match any real Windows path — see *The
dead-marker bug*. The pipeline had been discarding every file write and every
file create for the life of the project.

That is the pattern to distrust: a count that has never moved is evidence about
the detector at least as often as it is evidence about the samples. It was said
in this section, about this gap, before it turned out to be true of this gap —
the analyzer-attribution filter had already cost findings on every run for the
same reason.

Choosing the sample deliberately is what made it findable. The guest is
contained, so a downloader stalls at its first fetch and its dropped-file path
stays cold; Remcos was picked because it carries everything it needs and
installs before its first beacon, and its expected results were written down
*before* the run. Four of those expectations held and three failed, and all
three failures were pipeline bugs.

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

### 3. CLOSED — the spawn dump fired too early; the re-dump is proven

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

**Proven on four Remcos runs**, firing every time — child first seen at t1–t2,
re-dumped at t11–t12. It has not yet *revealed* anything, because Remcos drops
and executes rather than hollowing: `smng.exe` is already the payload at t1, so
the before/after pair is identical. The mechanism works; the case it was built
for still wants a sample that hollows a legitimate binary — see gap 5.

Three things still worth knowing:

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

**The sample's own process has never been dumped**, on any Remcos run. It exits
at ~t1 and the earliest offset tried was +2s; the skip record says so every
time. `1, 25` is the only remaining option if an image of the packer is wanted.

**On the loader, `1, 25` worked — and produced the before/after pair this feature
was built for, on the root instead of on a child.** The 20:23 run of 06 Aug dumped
pid 2448 twice: at t1, **12 MB**, 12 modules, 103 regions, `unmapped: 0`; at t25,
**123 MB**, 66 modules, 572 regions, `unmapped: 1` — and that one image is the
payload. The packer is caught before it unpacked and after, and the difference
between the two images is the payload appearing. Nothing was inferred from a
single dump.

That is worth reading against the re-dump's own record on the same run, which
fired nothing: all three children were skipped `exited before its +3s re-dump`,
and `RegSvcs` 4264 lived **2.14s** (spawned 4:25:33.44, WerFault at 4:25:35.58).
3s is still too late for this sample. **The lesson is that the pairing matters
more than the mechanism**: a scheduled offset on the parent got it where a
spawn-relative delay on the child could not, because the parent is the process
that lives long enough to be photographed twice.

### 4. FIRST PIECE BUILT — the chain-crashed warning, 06 Aug

The gap asked for something narrow and honest: nothing reported "the sample's
chain ended by crash", and a deliberate anti-analysis bail is indistinguishable
from a broken payload *from outside the guest*. Both leave a crashed process and
an otherwise quiet run. The pipeline cannot tell them apart, and the fix does
not pretend to.

What it does instead is refuse to let a crashed chain read as a clean one.
`summarize_abnormal_termination` (in `crash_evidence`) fires on either of two
witnesses:

- the Application Error 1000 events already attributed to the sample; and
- any `WerFault.exe` whose `-p <pid>` names a sample-tree process — the loader's
  `RegSvcs.exe -> WerFault.exe`, previously in `spawned_processes` and unused.

The second exists because a Windows build can fail to write the event, leaving
only the WerFault spawn; `witnessed_only_by_werfault` marks that case. It is
**not scored** — a crash is not evidence of malice, benign software crashes — so
it renders as a `card-alert` warning above the evidence, the same shape as the
observation-window caution: *treat an otherwise-empty run as inconclusive rather
than clean.*

Verified end to end against the loader's real tree: both witnesses agree, the
warning names `RegSvcs.exe (pid 9592)`, and it sits above the verdict.

### 4b. COLLECTION PATH BUILT — registry reads, 06 Aug

The *active* half of gap 4 — the sample reading a VM artifact and then going
quiet — needed registry reads in the event stream first. That collection path now
exists. The detector on top of it does not, deliberately: nothing about this is
scored, and it has not run live.

**The blocker was not where the gap said it was.** `INTERESTING_OPS` capturing
only Create/Set/Delete was true and was the smaller half.
`tools/procmon-configs/dynamic_default.pmc` carries **sixteen Operation *include*
rules** and `DestructiveFilter` is **1**, so a `RegQueryValue` is dropped at
capture time, never reaches `export.csv`, and is not in the PML either. Every
capture this project has written is missing them — a second export pass over an
old `raw.pml` recovers nothing. Procmon ANDs include rules across columns, so
scoping reads to VM paths at capture time is not expressible: adding Path
includes would drop every file, process and network event whose path did not
match. So the reads are captured unscoped and narrowed in the parser.

**`tools/procmon-configs/dynamic_registry_reads.pmc`** is the default config plus
`RegQueryValue` and `RegOpenKey`, generated by `dynamic_analysis/procmon_config.py`
rather than clicked together in Procmon's GUI — a `.pmc` is a binary blob with no
diff, and the two configs now differ by a line of code. The module reads and
rewrites the `FilterRules` entry; the round trip is byte-exact and tested, which
is the only cheap evidence that the format model is right. Whether Procmon loads
the result is a guest test and has not been done.

**It is opt-in, and the reason is volume.** Registry reads are the
highest-count operation on Windows. The 1148-second UPX run is the warning: 113k
events took 548s of teardown, and all of it was parsing. Pick this config
deliberately. A run whose *only* question is the VM check can be short — the
checks happen in the first seconds — but do not shorten a run that also wants
behaviour, because dormancy has reached +60s on the loader; pay the volume cost in
teardown instead. `RegEnumKey`/`RegEnumValue` are left out: they cost the most and
no common check needs them. The parser classifies them anyway, so a config that
does capture them still works.

**`dynamic_analysis/vm_artifact_reads.py`** is the pass. 50 markers over
VirtualBox, VMware, QEMU, Xen, Hyper-V, Parallels and Wine, plus firmware and
device identity. Attributed by lineage, off the *full* event stream. Three things
it does on purpose:

- **`specificity` splits `vm_specific` from `identity_surface`.** A
  guest-additions service key exists only on a VM, so reading it is an
  environment check and nothing else. `SystemBiosVersion` is where a VM check
  looks for "VBOX" *and* where an inventory agent looks for a BIOS version. A
  detector built on this must not treat them alike.
- **The result is half the finding.** `SUCCESS` on `…\Services\VBoxGuest` means
  the sample was told it is in a VM; `NAME NOT FOUND` means `vm_hygiene.ps1` held
  and the check came back clean. `BUFFER OVERFLOW` counts as found — it is the
  ordinary first half of a two-call value read, and reading it as a failure would
  report an artifact absent that the sample went on to read in full.
- **`collection_available` is the field to read first.** Zero artifacts read on a
  run that captured no reads is a statement about the config, not about the
  sample, and the report says so in those words instead of implying the sample
  did not look. Background reads by processes outside the tree are counted, not
  dropped: Windows enumerates every service key including the guest additions'.

`registry_read` is explicitly **never** a high-signal event. The fall-through in
`_is_high_signal_event` matches any suspicious path, so letting reads through
would put every process that so much as reads a Run key into
`suspicious_path_hits` — the same mistake as `registry_create` going from 5 to
140 when the service marker was repaired, at ten times the volume. Nothing
scored moves.

**Not mapped to ATT&CK, though T1497.001 is the obvious technique.** The mapping
is descriptive and computed after scoring, so it would be safe — but naming an
adversary technique off a detector whose false-positive rate has never been
measured on a live run is the thing this project keeps learning not to do. Map it
after a run shows what it fires on.

**The guard is proven and the finding path is not.** On 06 Aug 21:15 the pass ran
with no reads in the stream and refused to let that read as an answer about the
sample: `collection_available: false`, and the report saying **Registry Reads —
Not Collected** rather than a silent zero. That is the half of this worth having
first. What it has still never done is see a registry read.

**An earlier run meant to exercise this did not carry it at all.** The 20:23 detonation of
06 Aug was set up for it and tested none of it, because the guest was one commit
behind and the config field was still on the default. Two independent witnesses
in its own summary say so, and either alone would have been enough:

- **`vm_artifact_reads` is absent from `dynamic_run_summary.json`** while
  `abnormal_termination` is present — so the guest was at `9df8ec0`, the commit
  before the pass existed.
- **`procmon_summary` has no `registry_read` category, and `other` is 70 events
  out of 106,343.** Had the reads been captured, the older parser would have put
  every one of them in `other` and it would have been in the hundreds of
  thousands. So the capture used `dynamic_default.pmc`.

Nothing about the collection path is proven or disproven by that run. **Check the
summary for the field before reading its absence as a result** — see the
convention on pipeline version below, which this is the first instance of.

**What is still not built** is the detector: "read a VM artifact, then went
quiet". It wants a live run first, and the loader `422e30ed…` is still the case —
if its `RegSvcs.exe` reads `…\Services\VBoxGuest` before it faults, that is the
first evidence either way about a crash that has now been deterministic for seven
runs. Run it with the guest at `a387991` or later, the Procmon config field
pointed at `dynamic_registry_reads.pmc`, and read
`procmon\vm_artifact_reads.json`.

### 5. Carver recovers payloads; the `strong` branch has still not fired

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

**Parsing is proven; the finding path is not.** Across nine ProcDump images of
live malware it read 43 modules per dump with `rejected: 0` and
`resource_only: 0` — no false positives, clean parse. It has reported
`unmapped_images: 0` every time, correctly: Remcos's `smng.exe` is a normal
loader-mapped PE, so there is nothing foreign to find, and the loader sample's
payload was recovered before the carver existed.

**The premise this gap rested on now looks wrong, and the run that tested it is
the reason.** The plan was that `422e30ed…` maps its payload *alongside* the real
`RegSvcs.exe` image — the case the carver can see — so one detonation would earn
the `strong` branch. The 20:23 run of 06 Aug reported `unmapped: 0` on **every**
`RegSvcs` image: the spawn dump at t48, the exit dump at t48, the second
`RegSvcs` (pid 3420) at t51, and the WER crash dump — which
`crash_dump_preflight` confirms was written with full memory, `dump_type: 2`.
Eleven modules and about a hundred regions each.

This document wrote the failure criterion in advance: *"the carver reporting
`unmapped_images: 0` on a dump of `RegSvcs` taken after the payload was written
would mean the payload is written over the host image at its original base after
all."* The spawn dump alone could be a timing argument; the crash dump cannot,
because it was written after the fault. **Overwrite-in-place is now the
better-supported reading, and that is the documented blind spot** — the module
list is read from the memory the payload occupies, so there is nothing left to
compare against.

What keeps this a revision rather than a conclusion is that the known-module index
could in principle have suppressed a payload, and on that run ruling it out was a
*deduction*: the index suppresses only builds that another dump enumerated as
loaded, no dump enumerates either payload build, and `SmartOptimization.dll` was
reported unmapped in the root's own dump on the same run — so an identical build
inside `RegSvcs` would have been reported there too. Sound, and unreadable from the
report.

**That is now readable.** `per_dump` carries `known_module`, `resource_only`,
`inside_module` and `at_module_base` per dump, not only `unmapped` and `rejected`,
and the report lists any dump that set something aside under *What Each Dump Held*
— so "was a payload suppressed inside the hollowing target" is a column to read
rather than an argument to make. The run total is asserted equal to the sum of the
rows, so the two readings cannot drift. **The next run of this sample settles the
overwrite-in-place question directly**: `known_module: 0` on the `RegSvcs` rows
means nothing was set aside there and `unmapped: 0` is the real answer.

So the `strong` branch — `unmapped` inside a `HOLLOWING_TARGETS` process — still
has not legitimately fired, and this sample may not be able to make it fire.
`d712b6f9…` is the candidate now rather than the fallback: 1 MB .NET crypter,
vxCube reports *"unauthorized injection to a recently created process"*. The
finding path itself is not in doubt — it reported the loader's payload out of the
root process on this run, cleanly.

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
| Corroboration scoring | **Proven** across three samples and four bands — 35 / Needs Review, 70 / Elevated Attention, and 125 / Likely Malicious on Remcos with four categories and two strong. The band has moved for the right reason each time |
| Network attribution | **Proven.** `other_process_requests: 3` against the sample's own four processes, on a run where Windows was busy |
| PowerShell lineage filter | **Proven.** `blocks_from_sample: 12`, `other_process_blocks_excluded: 0` — the sample's own block survived, so the filter is not too tight |
| `activity_observed` | **Proven.** `false` before the fix and `true` after, on the identical sample and chain |
| Crash-as-injection | **Proven.** Fired on the hollowed `RegSvcs`, and moved the verdict a band |
| Crash-dump collection | **Proven**, and produced the payload |
| Adaptive window | **Fired, on the wrong case** — see below |
| Received-file collection | **Root resolution proven**; `received_files.roots` named the real `tools\fakenet\defaultFiles`. The *collection* path is still unproven — nothing has been uploaded since it was written |
| Containment refusal | **Proven** on 06 Aug. Guest armed with `vm_net.ps1 -Arm`, canary launched through the Dynamic Analysis window, and the run refused: `Not contained — a default route reaches the internet through a NAT gateway (Ethernet → 10.0.2.2). The guest is ARMED. The run has not been started.` It named the adapter and gateway and blocked *before* launch. The one time this was previously at stake it failed and malware got through; this time it caught it. Tested with the benign canary, so a failure would have cost nothing |
| Spawn re-dump | **Proven as a mechanism, and it has still revealed nothing.** Fired at t11 on a child first seen at t1, on live Remcos, which drops rather than hollows. On the loader at 3s it fired **not at all**: all three children were skipped `exited before its +3s re-dump`, `RegSvcs` having lived 2.14s. The pairing it was built for was finally produced by *scheduled offsets on the root* instead — see gap 3 |
| Parent-at-spawn dump | **Built, unproven.** The trigger no fixed offset can replace: the parent imaged at the instant it starts a child, which is when a loader is holding the stage it is about to write. Argued from eight runs of dormancy between +20 and +60s and two runs where +25s found the payload once and missed it once. It has never fired on a live sample |
| Offsets-pending-at-exit record | **Built, unproven.** The 21:15 run lost the packer image to an offset that never came due and recorded nothing; `_record_root_never_dumped` returns early once the root has any dump at all. Any process exiting with offsets ahead of it now names them |
| `procmon_filter` in the summary | **Built, unproven.** Which filter ran, its operations, and whether reads were captured — the setting a whole pass turns on and the only capture setting that was not in the record. Read from the file, not the filename |
| PE carve | **Recovered a real payload** — `SmartOptimization.dll`, a VB.NET assembly with forged Microsoft branding, from the loader's own process. Its `strong` classification on that run was a **false positive**: six copies of ntdll a suspended process had not yet enumerated. Fixed with the known-module index; the fix is unproven |
| Known-module index | **Proven twice.** 06 Aug 15:55 — `known_module_images: 6`, `unmapped_images: 1`, `unmapped_in_hollowing_target: 0`, verdict unchanged at 70 — and again at 20:23 on a two-`RegSvcs` chain with 9 reclassified. The ntdll false positive has not recurred, and the payload was reported both times |
| Multi-region carve | **Fixed, still unproven.** `regions_spanned: 1` again on 06 Aug 20:23. Two runs now with nothing spanning ranges, so it has never engaged; it correctly declined to bridge a gap |
| File-versus-mapped layout | **Proven** on 06 Aug 20:23 — the recovered payload reported `layout: "file"`, `truncated: false`. Held in file layout, measured against file layout, reported complete. Before the fix every such payload reported itself truncated against `SizeOfImage`, which is the mapped footprint |
| Dropped-file lineage | **Fixed, unproven.** Had none at all: a browser's writes counted as the sample's and took `payload_dropped` to strong on a loader that drops nothing |
| Carve on long paths | **Fixed, unproven.** A hash-named sample produced a 264-character path and the carve failed silently on the best image of the run |
| Crash-dump `hollowing_target` | **Fixed, still unproven.** The 06 Aug 20:23 crash dump carried no unmapped image at all, so there was nothing for it to classify. The bare WER stem used to lose the `.exe`, scoring crash-dump images `present` where live-dump images scored `strong` |
| File writes / dropped files | **Proven** on 06 Aug — 12 write events and the `%APPDATA%` drop, after being 0 on every run ever performed |
| `external_contact` on a bare IP | **Proven.** Fired strong on `62.60.226.68:24042` with no DNS lookup at all |
| Lineage on writes / paths / persistence | **Proven** on 06 Aug — persistence 14 → 2, Windows Update out of `top_written_paths`, exclusions counted |
| Dropped-file probe filtering | **Proven.** 13 candidates → 1, and that one exists on disk |
| Open-versus-production on file events | **Proven** on 06 Aug, 13:47. Every predicted number landed: hits 42 → 26, DLL probes 9 → 0, `svchost` opens 7 → 0, `file_write_events` 0 → 2 naming the drop |
| Sysmon Event 25 | **Enabled and silent.** Does not catch this technique; may catch others |
| Chain-crashed warning (gap 4) | **Proven on a live run**, 06 Aug 20:23 — both witnesses agreed, the card rendered above the verdict naming `RegSvcs.exe (pid 4264)`. The run also exposed `werfault_pid` reporting the crashed PID rather than WerFault's, now fixed; `chain_crashed` and `crashed_pid` were never wrong |
| Registry-read collection (gap 4b) | **Built, entirely unproven, and one run has already failed to test it.** Proven only against a synthetic Procmon CSV, which is the fixture problem this document warns about twice. The 06 Aug 20:23 detonation was set up for it and carried neither the code nor the config — see gap 4b for the two witnesses that say so. No run has ever captured a registry read. The first real one answers three things at once: whether Procmon accepts the generated config, what the volume costs, and what the markers fire on |
| `.pmc` filter rewrite | **Round-trip byte-exact** on `dynamic_default.pmc`, and the generated config re-parses. That the *format model* is right is well evidenced; that **Procmon loads it** is not tested and cannot be on the host. Check the run's `Operation` values before trusting an empty result |

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
once emitted `CONTAINMENT WARNING` and launched the sample anyway. It now refuses
the run — proven 06 Aug by arming the guest and watching it block a launch
before it started (see the proven table). Test your controls deliberately, and
test them with something that costs nothing when they fail: the armed detonation
that first exposed this was live malware, the run that proved the fix was the
benign canary.

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

**An operation name is not what the operation did.** Procmon's `CreateFile`
covers opening an existing file, and on one run 37 of 38 file events were
`Disposition: Open` while exactly one wrote anything. The detail field carries
the answer; the operation name does not. The same holds for the result — an
event that failed with "not found" observed an absence, and an absence is not
evidence of anything.

**Give every new pass the lineage the old ones have.** Findings, PowerShell
blocks and network records each got lineage attribution after a run proved they
needed it. Dropped files never did, and nobody noticed until a browser's writes
took `payload_dropped` to strong on a sample that drops nothing. When adding a
pass over the same events, the question is not whether it needs attribution —
it is which of the existing passes to copy.

**A path keyword says what happened, never who did it.** Every list of
suspicious paths is a statement about a *kind* of event, and the OS touches its
own autostart surfaces, task folders and service keys constantly. Attribution is
a separate question and has to be asked separately — but not of everything: a
payload written into a user-writable directory is a finding whoever produced it,
because a sample can cause a write it does not perform. Gate the surfaces, keep
the payloads.

**Repair a suppression list in the same change as the detector it guards.**
Every module with dead detection markers had dead exclusion markers too. A live
detector against a dead exclusion list is worse than both being dead, because
the analyzer writes thousands of files into the directory it is watching.

**Carve the image, then read it off the box.** The point of recovering a payload
is what static analysis then says about it, and that lives on the host, not in
another detonation. `SmartOptimization.dll` was identified — packer, decoy,
loading mechanism, absence of any config — from its own metadata with `pefile`,
and it retired a hypothesis the handoff had asserted for weeks. A recovered
artifact is a question answered on the bench, not a reason to run the VM again.

**A size is a size in some layout.** `SizeOfImage` describes a mapped image;
the section table describes a file; a payload in memory can be in either shape,
and a complete artifact measured against the wrong one reports itself as
damaged. Three explanations were tried for a 24 KB shortfall — a late dump, a
split memory range, a truncated read — before the answer turned out to be that
nothing was missing. When a measurement says something is incomplete, check what
it is being measured against before going looking for the rest.

**Absence from one list is not absence from the machine.** The carver's first
strong finding was six copies of ntdll, missing from a suspended process's
module list because the loader had not populated it yet. The check was sound and
the conclusion was wrong: "not in this list" meant "this list is incomplete", not
"foreign". Where a second source can confirm — another dump, another process,
another moment — ask it before calling something unaccounted for.

**A signal that fires on everything says nothing about anything.** The PE carver
reported eleven unmapped images in an idle Python process, all of them real and
all of them Windows resource files. Correctness was never the problem; the claim
was. Before trusting a new detector, run it against something known-clean — and
if it is a parser, against a file the operating system wrote rather than one
this repository built, because a synthetic fixture only contains what its author
already thought of.

**A change is not in the run until the guest has it, and the summary is what
says.** The 06 Aug 20:23 detonation was set up specifically to exercise the
registry-read pass and exercised none of it: the guest was one commit behind and
the config field still pointed at the default. The report looked completely normal
— `capture_quality: good`, every predicted number landing — because a *missing*
pass produces no warning, only an absent key.

**The cause was one step further back than it first looked**, which is the more
useful half. The work had been committed on the host and never **pushed**: the
guest's `origin/main` sat at `9df8ec0` because that is what the remote held, so its
pull was correct and returned nothing. `git log -1` in the guest names the code
that ran and would have caught it in one line. The chain is
`commit → push → revert → pull → disarm → detonate`, and it is an order rather
than a list — a pull before the revert is discarded with everything else, and a
pull before the push fetches the old commit and looks identical to success.

So: before reading a run as evidence about a new feature, check the guest's HEAD
before launching, and grep the summary for the field that feature writes
afterwards. Both are seconds; the run they save is five minutes plus a revert.

**A missing signal may be missing upstream of the code.** This document said for
weeks that registry reads were absent because `INTERESTING_OPS` did not list
`RegQueryValue`. True, and not the blocker: the Procmon config includes sixteen
operations and drops everything else *at capture*, so the parser was never given
one to classify. The same shape as Sysmon Event 25 being commented out in
SwiftOnSecurity's config — the pipeline was correct and the telemetry was not
there. Before writing a detector for something never observed, check that the
collector was asked for it, and check the tool's own live configuration rather
than the file that is supposed to describe it.

**Generate the binary config, do not click it.** `.pmc` files, snapshot settings
and GUI-set options are all changes with no diff and no record of what they
were. The registry-read config is produced from the default by
`procmon_config.py`, so the difference between the two is a line of code that
review can see — the same reason `bootstrap_tools.ps1` now applies the two
load-bearing guest settings instead of leaving them in a snapshot.

**Commit messages carry the evidence.** Every fix names the run that exposed it
and the numbers involved. `git log` is the incident record.

---

## Reading a run

Order to check things in, learned the hard way:

1. **`network_isolation.level`** from the run summary. `ok` now means contained;
   `uncontained` blocks the run outright. The GUI's line now re-reads every 4s
   while the window is open, as well as immediately before each launch, so
   arming or disarming the guest updates the strip and the armed banner without
   reopening the window. The summary is still the authority.
2. **Warnings first.** Degraded Collection, Cannot Be Reached, Name Resolution
   Was Not Served, Observation May Be Incomplete. Each one means part of the
   run is unobserved rather than quiet.
3. **`Capture` column** on the dumps. `Live (smeared)` qualifies every YARA
   result from that image. A PID appearing twice, once `process-spawn` and once
   `spawn-redump`, is a before/after pair — a size jump between them is a
   payload being written in. **`parent-at-spawn` is the row to look at on a
   loader**: that image was taken at the instant the process started a child,
   which is when it is holding the stage it is about to write. And read the
   skipped list for `offset(s) ... still pending` — an image nobody took is not
   an image that held nothing.
4. **Evidence Behind The Verdict.** Which categories fired and which were judged
   strong. The score is descriptive; this is the reasoning.
5. **Crashes In The Sample's Tree.** A fault outside any mapped module is
   injection evidence, and often the only record of hollowing. Read it together
   with **Virtual-Machine Artifacts The Sample Read** — a crash after a
   guest-additions check is a different run from a crash after nothing. That
   section says `Not Collected` unless the run used
   `dynamic_registry_reads.pmc`, and that is a statement about the config.
6. **Executables The Loader Never Mapped.** Structural, so it works where a
   signature does not: the 05 Aug payload matched no rule in the set and was
   conclusive from its headers. Read the two timestamps side by side — an image
   years newer than the process hosting it did not ship with it. Then read *What
   Each Dump Held* underneath it: a zero in `Unmapped` on a hollowed process only
   means "no payload" if `Known module` is zero there too.
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
| Dormancy | +20, +24, +42, +48, +60s across seven runs — still widening |
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
strings, no family markers. That is why YARA matched nothing across nine images
while the UPX control passes — there is nothing for a signature to key on, and
the ruleset is not at fault.

**What that payload actually is — settled by static analysis, 06 Aug.** The
carved image (`SmartOptimization.dll`, 57,344 bytes, x86 .NET) was parsed with
`pefile` on the host. Its metadata `#Strings` heap decides it:

- **Packed with SmartAssembly**, a commercial .NET protector — the namespaces
  `SmartAssembly.Attributes`, `.Delegates` and `.HouseOfCards` are its
  signature. This is the "obfuscation" every prior run described.
- **The visible program is a sliding-puzzle game.** Its managed resource holds
  a full Windows Forms UI — `tileButton`, "Puzzle solved!", "Moves:", a
  File/Edit menu. A complete benign application used as the decoy carrier.
- **The loader primitives are all present**: `System.Reflection.Emit`,
  `GetManifestResourceStream`, `FromBase64String`, `Invoke`/`BeginInvoke`. It
  pulls a resource, base64-decodes it and invokes it reflectively.

**The config is not in this image, and the old hypothesis was wrong.** The
handoff said for weeks that "the config lives in a 2,380-byte `.rsrc` blob, a
static-analysis job on the carved image." Checked directly: the win32 `.rsrc` is
1,122 bytes of forged version info, the one managed resource is 4,267 bytes of
puzzle-game UI strings, `.text` entropy is 5.90 and there is no high-entropy blob
anywhere — no embedded encrypted stage 3. The Remcos config lives in the stage
this loader would reflectively invoke, which the crash prevents. That is the
single explanation for every prior observation: no C2, no Run key, no dropped
file, and no YARA match on any image.

**This explains three runs of empty findings.** The chain dies at stage 2: the
loader hollows `RegSvcs`, stage-2 starts, and it faults before decrypting stage
3. There was never going to be a C2 connection, a Run key or a dropped file.
Persistence and dropped-files sitting at `0` for this sample is a property of
the sample, not a gap in the pipeline.

**The crash is deterministic** — same chain, same failure point, three runs. Not
flaky hollowing, and not Defender, which has real-time protection off. What
remains is anti-analysis or a broken crypter, and the pipeline cannot currently
tell those apart (gap 4).

### The 06 Aug 21:15 run — the guard held, the config did not, and the packer got away

`run_id 9e69fcbc`, 252s, 98,540 Procmon events, clean baseline
(`autoruns before_total: 1601`). The eighth run of this sample and the first with
the registry-read code on the guest.

**The code was there and the reads were not.** `vm_artifact_reads` is present and
reports `collection_available: false`, `reads_in_stream: 0`, with the note naming
`dynamic_registry_reads.pmc`; the report renders **Registry Reads — Not
Collected**. So gap 4b's *guard* is proven on a live run — a zero that would
otherwise have read as "the sample checked nothing" was refused — and its finding
path still is not.

**And the run could not say why, which is now fixed.** Two explanations fitted
equally: the config field was still on the default, or the generated config was
selected and Procmon ignored the rules added to it. The event mix is identical
under both. The summary recorded the dump offsets, the process cap and the
re-dump delay and said nothing about the filter, so `procmon_filter` now carries
the config path, its included operations and `captures_registry_reads`, read out
of the file rather than off the filename. It renders in Capture Configuration and
in the not-collected card, and a filter that cannot see reads is announced at
launch instead of after the teardown.

**The packer image got away, and the record was silent about that too.** Dormancy
was **+23s**. The root was dumped at +1s — 122 MB, 65 modules, `unmapped: 0` —
spawned `RegSvcs` at +23s, and was gone by +24s with the +25s offset never coming
due for it. `unmapped_images: 0`, `carved: 0`. The previous run's payload came
from that exact offset. The summary showed 9 dumps, 1 skip, 2 failures and
**nothing at all** about the missing image: `_record_root_never_dumped` returns
early once the root has any dump, which is what made it invisible. Now any
process that exits with scheduled offsets ahead of it records them by name.

**Which produced the better instrument.** Across eight runs this sample's dormancy
has been +20, +23, +24, +42, +48 and +60s, so the parent's useful window —
`[unpack, spawn + ~1s]` — moves by forty seconds and a fixed offset lands in it by
luck. **The parent is now imaged at the moment it spawns a child**, trigger
`parent-at-spawn`, suffix `_atspawn`. That instant is a property of the technique:
the loader has decrypted the next stage and is about to write it into the process
it just created. Once per parent, caps honoured, refusals recorded — and ordered
*before* the child's own dump, because the parent has about a second left while
the child's spawn image has been an empty shell on every run so far, and losing it
is recorded as a skip.

**Both of the previous run's fixes verified live.** `crashed_pid: 8428`,
`werfault_pid: 10096`, `spawned_by_pid: 8428` — three PIDs, correctly told apart.
And *What Each Dump Held* settled the question it was built for on its first
outing: the `RegSvcs` spawn dump shows `known_module: 0` alongside `unmapped: 0`,
so nothing was suppressed there and the zero is the real answer; the crash dump
shows `known_module: 2`, so its zero stays qualified. That was a deduction one run
ago.

Everything else held: 70 · Elevated Attention, `process_injection` **strong** on
the crash alone (`0 unmapped PE image(s)` contributed nothing this time),
`scripted_execution`, PowerShell 12/1, YARA 0 across 10 dumps,
`missed_descendants: 1` naming WerFault 10096, `chain_crashed` on both witnesses.

### The 06 Aug 20:23 run — void for gap 4b, and it moved gap 5

The seventh detonation of this sample, run against the prediction recorded below.
`run_id 253c1d72`, 311 seconds, 106,343 Procmon events, `capture_quality: good`.

**It tested none of what it was set up for.** Guest one commit behind and the
Procmon config field still on the default — see gap 4b for the two witnesses. The
registry-read collection path remains entirely unproven.

**What the prediction got right, exactly:** score **70 · Elevated Attention**,
`process_injection` **strong** by the crash route with `scripted_execution`
alongside; PowerShell `blocks_from_sample: 12`, `blocks_suspicious: 1`,
`other_process_blocks_excluded: 0`; `sysmon_injection_events: 0` with Event 25
silent again; `RegSvcs.exe` faulting `0xc0000005` at `012b521d` with no faulting
module, `crashes_in_hollowing_target: 1`.

**The chain-crashed warning fired on a live run for the first time.** Both
witnesses agreed, naming `RegSvcs.exe (pid 4264)`, and the card rendered above the
verdict. It had only ever been verified against recorded records before this.

**Three results worth keeping:**

- **The root was dumped at t1 and t25, and the payload is in the second.** The
  before/after pair, on the parent rather than a child — see gap 3. The carved
  image is `SmartOptimization.dll` again: 81,920 bytes, x86 .NET, `0x6a71514c` =
  2026-08-04, at `0x5320000` in `…_2448_t25.dmp`.
- **The known-module index held a second time, on a different chain shape.**
  `known_module_images: 9`, `resource_only_images: 22`, `rejected: 0`,
  `unmapped_in_hollowing_target: 0`. It was already proven at 15:55 with 6; this
  run had two `RegSvcs` rather than three and reclassified 9, with the
  six-copies-of-ntdll false positive still absent and the payload still reported.
  Suppress the system DLLs, keep the payload, which is exactly what it was for.
- **File-versus-mapped layout is proven too.** The payload reported
  `layout: "file"`, `truncated: false`, `regions_spanned: 1`. Held in file layout,
  measured against file layout, and reported complete. The multi-region carve
  still has not engaged — nothing spanned ranges.

**And one that contradicts the plan:** every `RegSvcs` image reported
`unmapped: 0`, including the full-memory crash dump. That is this document's own
written failure criterion for gap 5, and gap 5 now says so.

**Deltas from the previous six runs.** Dormancy **+48s**, so the spread is
+20, +24, +42, +48, +60 — still widening. **Two** `RegSvcs` this time rather than
three, and `missed_descendants: 0` against 3 on the 05 Aug run. The chain is
`sample → powershell.exe Add-MpPreference → RegSvcs.exe (4264, faults at +2.1s) →
WerFault.exe (7976)`, with a second `RegSvcs` (3420) at t51.

**One defect, cosmetic, and one worth watching:**

- `werfault_witnesses[].werfault_pid` reported **4264**, the crashed process's
  PID. WerFault was **7976**, in the spawn detail. The field was reading the
  record's own `pid`, which on a process-create event is the *creating* process —
  and because the crashing process is what spawns WerFault, the wrong value was
  the right number twice over. Fixed to read the created PID from the detail, with
  `spawned_by_pid` keeping the other question. `chain_crashed` and `crashed_pid`
  were always correct, so nothing downstream was wrong. The test fixture had
  encoded the same misunderstanding, which is why review would not have caught it.
- **The first Sysmon Event 8 this project has ever recorded — and it was ours.**
  `<unknown process> → dumpcap.exe`, correctly classified as analyzer activity and
  excluded, so `injection_events` stayed 0 for the sample. The exclusion did its
  job on the one occasion it has had.
- **WER's `192.0.2.123:443` landed in `sample_destinations`.** The smaller gap
  below, manifesting for real: `WerFault` is sample lineage, so its Windows Error
  Reporting upload attempt counts as the sample's traffic. It cost nothing — 443
  is a standard port and no domain was notable, so `external_contact` correctly
  did not fire — but it is no longer hypothetical. FakeNet's own table names
  `wermgr.exe` at the same address, which is the corroboration.

### The earlier 06 Aug re-run — the carver's finding path fired

**Gap 5's `strong` branch has now been exercised.** The carver reported
`unmapped_in_hollowing_target: 2` inside a hollowed `RegSvcs.exe`, so
`process_injection` reached strong by a route independent of the crash. On real
dumps it also set aside **14** resource-only images without a single false
positive, and rejected nothing.

**But the premise gap 3 was built on turns out to be wrong for this sample.**
The *spawn* dump — `RegSvcs.exe_10784_t20.dmp`, 15 MB — already contained both
unmapped images. Hollowing was complete before the watcher ever saw the child.
The re-dump never fired at all: all three children exited before +3s, and the
skip records say so. "Every `RegSvcs` image is a 15 MB empty shell" came from
runs where nothing was reading the images structurally — nobody could tell the
shell was not empty. The re-dump remains sound for a slower loader; it was never
needed here.

**Dormancy is now +20, +24, +42, +48, +60s** across seven runs. The spread keeps
widening, which was the argument for the re-dump — though on this chain the
re-dump is the wrong instrument regardless, because the children die in 2s. What
the spread really argues against is a *fixed offset* catching a child at all.

**The 1.8 MB images were `ntdll.dll`, and the finding was a false positive.**
Static analysis of the carved files settled it: sections `.text`, `RT`, `PAGE`,
`.mrdata`, `.00cfg`, no import table, and strings reading
`.text$lp00ntdll.dll!20_pri7` and `CLIENT(ntdll): Found CheckAppHelp`. So
`unmapped_in_hollowing_target: 6` was six copies of ntdll, and
`process_injection` reaching strong by the carver route on that run was not
earned. The crash route fired legitimately, so the verdict stood — for one
reason rather than two.

The cause is in the data: those dumps enumerate **6 and 11 modules** while the
loader's own dump enumerates **65**. A process created suspended — which is
exactly what hollowing does — has ntdll mapped before the loader has populated
its module list, so the DLL is physically present and legitimately absent from
the list the carver checks against. See *The known-module fix*.

The year-2081 timestamp was the tell, built in and then not read. Microsoft's
reproducible builds put a **hash** in `TimeDateStamp` rather than a build time,
so `0xd277d290` was never a date. The plausibility bound was the year 2100, so
it rendered as "2081-11-22" instead of as nothing.

### The payload, recovered and self-describing

The image that mattered was in the loader's *own* process, not in `RegSvcs`: an
81,920-byte x86 **.NET** PE, importing only `mscoree.dll`, written in VB.NET
(`Microsoft.VisualBasic.CompilerServices`). Its version resource:

| | |
|---|---|
| CompanyName | `Microsoft Corporation` |
| FileDescription | `Microsoft Smart Optimization` |
| OriginalFilename | `SmartOptimization.dll` |
| ProductName | `Smart Optimization` |
| FileVersion | `2025.2.0.14826` |
| LegalCopyright | `Copyright © Microsoft Corporation 2026` |
| TimeDateStamp | `0x6a71514c` — 2026-08-04, two days before the run |

**There is no Microsoft product called "Smart Optimization".** This is the
unpacked stage wearing forged Microsoft branding, and it is the first payload
this pipeline has recovered *and named* without anyone carving by hand.

**It reported 57,344 of 81,920 bytes and was complete all along.** Two theories
came and went before the right one. It was never a timing problem — a later dump
would not have helped — and it was not a split across memory ranges either,
though the carve now handles that case too. `SizeOfImage` is the **mapped**
footprint: what the loader spreads an image into once section boundaries are
rounded up to pages. This payload sits in memory in **file layout**, as a raw
blob, which is what `Assembly.Load(byte[])` and every decrypt-then-map loader
produces — precisely the state a dump of the *unpacking* process catches.

The evidence it was whole: 57,344 bytes matches the 05 Aug hand-carve exactly,
two extractions months and methods apart; `pefile` read the complete version
resource out of it, which a cut-off `.rsrc` would not have allowed; and the
section table sums to about 54 KB, which fits inside 57,344 with page padding
to spare.

So the carver now computes the file-layout size — the end of the last section's
raw data — and reports which shape it found: `layout: "file"` or `"mapped"`,
with `truncated` measured against whichever applies. **A payload in file layout
has not been mapped yet**, which is worth knowing on its own: it says where in
the chain the dump caught it.

The carve also follows an image across *virtually contiguous* ranges now, and
records `regions_spanned`. It deliberately stops at a gap: the rest was not
captured, and splicing the next range on would fabricate an artifact rather than
truncate one.

### The known-module fix

An image not covered by *this* dump's module list, but enumerated as a loaded
module by *any other* dump in the same run, is now classified `known_module` —
counted like `resource_only`, never scored, never carved.

Matched on `(TimeDateStamp, SizeOfImage)` rather than on a name. That pair
identifies a build, it is present both in a minidump's module list and in a
carved image's own header, and it needs no list of system DLLs to keep in step
with a Windows version. On the run that exposed this it would have reclassified
all six ntdll copies and left `SmartOptimization.dll` untouched — nothing
enumerates that anywhere.

It costs a first pass over the run's dumps to build the index, which is cheap:
the module list is a stream, not a scan.

`_iso_timestamp` now renders nothing for a date in the future rather than a
plausible-looking one, so a hash in `TimeDateStamp` reads as absent instead of as
2081.

### Three defects the run exposed, all fixed

1. **The carve failed on Windows' 260-character path limit.** Samples are stored
   under their SHA256, so `_carve_name` produced a 68-character process fragment;
   with the case id and a timestamped run id in the path that came to 264
   characters and failed with a bare `[Errno 2] No such file or directory`. The
   name fragment is now capped at 24 (264 → 220), and both the write and the
   `mkdir` go through a `\\?\` long-path form, because a deep enough case
   directory exceeds the limit whatever the image is called.
2. **`payload_dropped` reached strong on a sample that drops nothing.** Two
   libraries written by `msedgewebview2.exe` — not sample lineage at all —
   plus two `__PSScriptPolicyTest_*.ps1` files, which PowerShell writes on every
   invocation. `collect_dropped_file_candidates` had no lineage filter; the
   findings and the PowerShell blocks had been given one and dropped files were
   missed. It now takes `descendant_pids`, with `None` meaning "could not
   resolve, count everything" rather than an empty tree, and the policy-probe
   name is in the noise list.
3. **The crash-dump route silently downgraded itself.** WER writes
   `RegSvcs.10784.dmp`, and the collector recorded the bare stem `RegSvcs` —
   which is not in `HOLLOWING_TARGETS`, so the same carved image classified
   `hollowing_target: false` from a crash dump and `true` from a live one. The
   extension was already being computed there for the attribution test and then
   discarded. **This is the loader's historical case**: on the three earlier
   runs the crash dump was the *only* image of `RegSvcs`, so the finding would
   have been `present` where it should have been `strong`.

### The prediction that was recorded before it ran

**It has now been run against, and the scoring is in *The 06 Aug 20:23 run*
above.** Short version: everything predicted about the chain, the score and the
crash landed exactly; gap 3's re-dump prediction failed because the children die
inside 3s; gap 5's failed in the informative direction, which is what revised the
gap; and gap 4b's was never tested, because the run did not carry the code. Left
here unedited, because a prediction rewritten after the fact is worth nothing.

**That advice is superseded.** This section used to end "if you return to this
sample, the `.rsrc` blob is a static-analysis job, not another detonation." That
was correct when written: nothing in the pipeline would have seen anything new.
Two features have been built since that have never met it, and both were built
*for* this chain.

Recorded before the run, on the same principle as the Remcos section: an
expectation written in advance makes the detonation a pass/fail test of the
pipeline rather than a description of the sample.

**Why this sample and not a new one.** It is the only sample here that hollows a
binary in `HOLLOWING_TARGETS`, and its payload is mapped *alongside* the real
`RegSvcs.exe` image rather than over it — which is exactly what the carver can
see, the overwrite-in-place variant being the documented blind spot. The two PE
headers were already confirmed by hand: RegSvcs at `0x5ff2b99b`, the payload
carrying a 2025 one.

**Settings, and both differ from the Remcos runs:**

| Setting | Value | Why |
|---|---|---|
| `spawn_redump_seconds` | **3**, not 10 | The payload faults. At 10s the record reads `exited before its +10s re-dump` instead of producing an image. Hollowing completes in well under a second, so 3s is after the write and before the crash |
| Offsets | **1, 25** | Dormancy is 20–60s, so +1s catches the parent while it is still alive. **This worked**: t1 and t25 imaged the root and the payload is in the second — the pair, on the parent |
| Max processes | 20 | Six-process chain, plus re-dumps |
| Procmon config | **`dynamic_registry_reads.pmc`** | The only way a VM check is visible. Unproven with Procmon, so check `export.csv` has `RegQueryValue` rows before reading an empty result as "it did not look" |
| Window | 180s, and **untick *Extend if dormant*** | Do not shorten it for the reads: dormancy has reached +60s on this sample, and the other two gaps this run is for need the payload to actually start. The volume cost of the read config is paid in teardown instead — that is the right side to pay it on |

**What each gap should get:**

- **Gap 5, the finding path.** The carver should report `unmapped` inside
  `RegSvcs.exe`. Because `RegSvcs` is in `HOLLOWING_TARGETS` this fires
  **strong** — the branch that has never been exercised on any run. Expect the
  carved image to be an x86 .NET EXE of 57,344 bytes, compiled 2025-06-18.
  Compare its SHA256 against the hand-carved copy.
- **Gap 3, the revelation.** The spawn dump should catch `RegSvcs` as a ~15 MB
  empty shell and the +3s re-dump the same PID with the payload in it. A size or
  hash difference between the pair is the whole point of the feature and has
  never been seen.
- **Gap 2.** `sysmon_injection_events: 0` again, and Event 25 silent again. The
  crash route should fire `process_injection` **strong** as it did on 05 Aug.
- **Gap 4.** The chain-crashed warning should fire on both witnesses, as it did
  against this tree's recorded records. **And with
  `dynamic_registry_reads.pmc` selected as the Procmon config, the run answers the
  open question about this sample:** whether `RegSvcs.exe` reads
  `…\Services\VBoxGuest`, an ACPI table signed `VBOX__` or `SystemBiosVersion`
  before it faults. A deterministic fault six runs deep with a VM check in front
  of it is anti-analysis; the same fault with no check is a broken crypter. Either
  answer is the first real evidence. Watch two things that would make it a
  collection failure rather than a finding: `Operation` values in `export.csv`
  containing no `RegQueryValue` at all, which means Procmon did not accept the
  generated config, and a teardown much longer than the last run's, which is the
  volume cost landing.

**Expected, from three previous runs:** chain sample → `powershell.exe
Add-MpPreference -ExclusionPath <self>` → 3× `RegSvcs.exe` within 15 ms; one
faults `0xc0000005` in unmapped memory, the others die inside one poll interval;
12 PowerShell blocks with 1 suspicious; score 70 · Elevated Attention with
`process_injection` (strong) + `scripted_execution`.

**What would make it a failure rather than a finding:** the carver reporting
`unmapped_images: 0` on a dump of `RegSvcs` taken *after* the payload was
written. That would mean the payload is written over the host image at its
original base after all, and the 05 Aug hand-carve found it alongside only
because the crash dump caught a different moment.

**The static-analysis question is now answered** — see *What that payload
actually is* above. The carved image is a SmartAssembly-protected reflective
loader disguised as a puzzle game, with no config anywhere in it; the config is
in the stage it would invoke, and the crash prevents that. There is nothing more
this sample yields without defeating SmartAssembly, which is a reverse-
engineering job on stage 2, not a pipeline task and not another detonation.

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

### The 03:56 clean-baseline run — the fixes proved out, and exposed three more

| | 02:54 | 03:56 |
|---|---|---|
| `file_write_events` | 0 | 12 |
| Dropped candidates | 0 | 13 |
| `external_contact` | absent | **strong** |
| `autoruns_suspicious` | 3 | 2 |
| Score | 70 · Elevated Attention | **140 · Likely Malicious** |

`%APPDATA%\Roaming\Config\smng.exe` appeared 30 times in the suspicious-path
hits, from both the sample and `smng.exe`. `external_contact` fired strong off
`62.60.226.68:24042` with no DNS involved. The spawn re-dump fired at t12 for a
child first seen at t2, and both root-skip records were present.

**Then the same run showed what letting file events through had not been
prepared for.** All three were invisible while the markers were dead:

- **Eleven of the thirteen "dropped files" did not exist.** `WINMM.dll`,
  `urlmon.dll`, `WININET.dll`, `iertutil.dll` in `%APPDATA%\Roaming\Config` —
  `smng.exe` walking the DLL search order in its own directory. Failed opens.
  `payload_dropped` reached **strong** on a true count of one. Now filtered on
  the Procmon result, deliberately as a not-found list rather than "keep only
  SUCCESS", because a file written and then deleted is still a drop.
- **`persistence_hits`, `suspicious_path_hits` and `top_written_paths` were
  never attributed by lineage.** `svchost.exe` rewriting
  `\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Work` supplied 12 of 14
  persistence hits and *every* row of `top_written_paths`. They now follow the
  same collect-then-filter pattern the network records already used — with one
  exception, below.
- **FakeNet's own WinDivert driver counted as a finding**, three times. It
  unpacks into `%TEMP%\_MEInnnnn`, which contains none of the workbench's
  directory names. The exclusion had to be added in **two** places: `findings`
  and `dropped_file_triage` keep separate analyzer lists, and repairing only the
  first still left `payload_dropped` strong on our own driver plus one real drop.

**Not everything is lineage-gated, and the split is deliberate.** An OS
persistence surface is touched by Windows constantly and only means something
when the sample touches it. An executable or script written into a user-writable
directory is notable whoever produced it, because a sample can cause a write it
does not perform — through injection, COM, a service or WMI — and lineage cannot
see that. Gating both would have thrown away a payload dropped into `%TEMP%` by
an injected `svchost.exe`. Two existing tests failed when the first version of
this fix collapsed the two, which is how the distinction got found.

Replaying the run through the fixed code: persistence 14 → 2, suspicious paths
39 → 19, dropped 13 → 1, `top_written_paths` now the drop instead of Windows
Update, and **125 · Likely Malicious** with `payload_dropped` correctly
`present` rather than strong. The verdict band does not move — two genuinely
strong categories carry it either way — which is the point: the score was right
for partly wrong reasons.

The report now lists the dropped files with an **On disk** column, rather than
only the counts. That column is what would have shown this at a glance.

### The 04:38 run — the attribution fixes proved out

**125 · Likely Malicious**, exactly as the replay predicted. `payload_dropped`
correctly `present` on one real drop that exists on disk; `persistence_hits` 2
rather than 14; `top_written_paths` empty of Windows Update; dropped candidates
1 rather than 13 with none missing.

It also showed two more instances of the same fix applied in only one place, and
one honest naming problem:

- **The not-found filter was in `dropped_file_triage` and not in `findings`.**
  Nine non-existent DLLs stayed in `suspicious_path_hits` while being correctly
  absent from the dropped-file count. Third time a fix has needed applying to a
  sibling module.
- **The notable-whoever-produced-it exemption was applied to any event naming
  the path**, so `svchost.exe` *opening* the payload six times — Defender and
  the indexer noticing a new executable — was exempted from lineage along with
  the drop itself.
- **`file_write_events: 0` on a run that dropped a PE.** The tile grid read
  "File Writes 0" beside "Dropped Files 1", because only `WriteFile` counted and
  Procmon logged the drop as a `CreateFile`.

**A CreateFile is not a creation**, and the disposition in the detail is the only
thing that says which. The proportions make the case: of 42 suspicious-path hits
on that run, exactly **one** carried `Disposition: OverwriteIf` — the write of
`smng.exe`. The other 37 file events were all `Disposition: Open`.

Replayed: suspicious paths 42 → 26, DLL probes 9 → 0, svchost opens 7 → 0,
`file_write_events` 0 → 1 with `top_written_paths` naming the drop.

One distinction that cost a test to find: **"is this a mere open" does not apply
to events that are not file operations at all.** The first version tested for
production and used it to gate the exemption, which suppressed a process create
of a relocated executable — a finding whoever started it, with its own existing
test saying so. The two are now inverse tests rather than the same one.

### The 13:47 run closed it

Every predicted number landed exactly: hits 42 → **26**, DLL probes → **0**,
`svchost` opens → **0**, `file_write_events` 0 → **2** with `top_written_paths`
naming `smng.exe`, and the score unchanged at **125 · Likely Malicious** — the
fix cleans the evidence lists without touching the verdict, which is what it was
supposed to do.

The kept hit list now reads end to end: 17 sample and 4 `smng.exe` opens of the
payload, one write, one process create, two Run keys, one image load. Nothing
else.

`background_persistence_hits` was **0** on this run against 10 on the last one,
because Windows Update did not touch its scheduled task during the window. That
is the filter having nothing to do rather than not working — and the count is
what says which, which is the entire reason those counters exist.

**This is the Remcos sample finished.** Gap 1 is closed on both halves, the spawn
re-dump is proven, and the carver's parsing is proven on real dumps. What is left
is listed below and needs different samples, not another run of this one.

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
