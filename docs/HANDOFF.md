# Handoff

State of the work, for picking up in a fresh session. `docs/WORKFLOW.md` is the
run procedure; this is what is done, what is known-broken, and what is worth
doing next.

**Last updated:** 2026-08-09. **The stage-2 payload `na3PRqPuA2` is decrypted; stage
3's own inner blob is not.** Stage 3 turned out to be a native x86 loader carrying a
272 KB packed blob, and that blob defeats static attack outright — no periodicity, no
repeated blocks, nothing from XOR/additive/recurrence/RC4 across 55 candidate keys.
Emulating the stub (`scripts/emulate_native_stub.py`) gets much further: no imports
needed, `NtAllocateVirtualMemory` for `0x457e1` bytes, self-relocation, jump into the
allocation, and real unpacking. It was twice reported here as **stalling**; it does
not — single-stepping found RC4 PRGA at `0x40231f` running to completion, and the
progress check had been watching an allocation while the output went to the stack.
Whether the emulation *diverges* on a wrong API answer is the real open question; see
*Stage 3's inner blob*. The
inverse index over the proxy map was built, the call graph rebuilt behind it, and
it reached the decryptor: `#470 ConcatAllocator`, a hand-rolled byte recurrence with
the ASCII key `HREWPjFNAr` — **not AES**, which is why 792 AES combinations had
failed. The key was recovered algebraically from a known PE header rather than
guessed, and what came out is a **native x86 PE32 carrying its own 272 KB encrypted
stage**, so the config and C2 are one layer further down. Two things fell out of it
that the pipeline should know: the IL decoder was missing every comparison branch
and `endfinally`, silently corrupting exactly the flattened methods worth reading
(now 0 undecoded bytes in 61,113 instructions), and **stage 3 carries `RegSvcs.exe`'s
own `TimeDateStamp`**, which defeats the timestamp comparison *Reading a run* tells
you to make. See *The call graph, rebuilt*. Before that, the bench gained a .NET
toolchain (ILSpy 11, SDK
10.0.302, de4dot built from source). Stage 2 was lost, re-acquired on the first
re-run, and then partly eaten by Bitdefender — it survives XOR-wrapped on the
external drive. Its resources are now named rather than guessed at, its flattening
is defeated (both opaque predicates are constant), and an AES key was recovered by
executing the builder statically — for the wrong target, which is the better half
of that sentence. Before that, the
loader's tenth run (`5457f804`, 14:53) was the first ever to capture a registry
read. Gap 4b's collection path is proven end to end,
Procmon accepts the generated `.pmc`, and the volume cost is 2.2x events for 281s. Its
nine hits were all Windows rather than the malware, which is now fixed and counted, and
the negative that remains is a real answer: **this sample does not check for a VM.**
Before that, stage 2 was read at the IL level: an AES-256 key and
IV recovered, the key-shaped string literals shown to be decoys, two
architecture-specific trampoline stubs found in the field data, and the protector's
**proxy-delegate map decrypted — 1,181 bindings, no key needed** — which exposed a
capability set nobody had seen, including `WebClient::DownloadFile` and `Process::Kill`.
The payload resource `na3PRqPuA2` is still encrypted, and that is now a de4dot job
rather than a decompiler one. The reader is `scripts/dotnet_meta.py`; see *Read at the
IL level*. Before that, the
loader's ninth run (`f3d26e46`, 04:41),
where `parent-at-spawn` fired for the first time and recovered an **892 KB x86 .NET
assembly that exists in no other dump** — the first artifact here that no choice of
offsets could have caught. It has since been identified on the bench: stage 2, forged
as `MemCompress Pro`, carrying the injection API set as split UTF-16 fragments and a
278 KB AES-encrypted resource that is now the highest-value open item. Two of this
document's standing conclusions are retracted as a result — see *The 892 KB stage*. The same run read 90 · Likely Malicious on a `dwm.exe`
injection event, which was not earned: the Sysmon highlight pass had no lineage
attribution, the fourth instance of that bug in this pipeline, now fixed. Registry
reads are still uncollected, on the third attempt. Before that, the eighth run
(`9e69fcbc`, 21:15) —
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
the config is in the stage it would invoke, which the crash prevents. Its stage-2
payload was decrypted on 09 Aug and is **another loader**, native x86, wrapping a
further 272 KB encrypted stage — so "the config is one stage down" has now been
true twice, and there is no evidence yet about how deep it goes. See
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

- **The host bench now has a .NET toolchain, and it was assembled piecemeal.**
  ILSpy 11 (standalone zip, Avalonia — it wants the base **.NET 10 runtime**, not
  the Desktop one, despite older ILSpy being WPF), and **.NET SDK 10.0.302**,
  which arrived with the .NET 10 install and is what makes `dotnet build`
  possible at all. Runtimes 6.0.16, 7.0.4, 8.0.8 and 10.0.10 are side by side;
  installing a new one takes nothing away.
- **de4dot is built at
  `G:\tools\de4dot-master\de4dot-master\Release\netcoreapp3.1\`**
  and needs two workarounds that are not obvious from its README. The source is
  2018-era and `LangVersion` is `latest`, so C# 14 makes `field` a keyword inside
  property accessors and `ProxyCallFixer.cs` fails to compile — build with
  `-p:LangVersion=9.0`. And it targets `netcoreapp3.1`, which is not installed,
  so run it with `DOTNET_ROLL_FORWARD=LatestMajor dotnet de4dot.dll`. Full
  command:

      dotnet build de4dot.netcore.sln -c Release -f netcoreapp3.1 -p:LangVersion=9.0

- **The host's antivirus is Bitdefender, not Defender.** `WinDefend` is stopped
  and Defender registers as passive; Bitdefender is the active engine. Worth
  knowing for two reasons: it is the same engine whose `Gen:Variant.Rescoms`
  label the Remcos section cites, so it is aggressive on exactly this class of
  file; and `Get-MpComputerStatus` fails with `0x800106ba` on this host, which
  reads like an error and only means Defender's service is off. Carved payloads
  kept on disk want a password-protected zip rather than an AV exclusion — it
  stops on-access scanning of the contents without opening a hole.

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

- **CLOSED — `WerFault.exe` counted as sample lineage for network attribution.**
  Correctly, in that the sample caused the crash, and misleadingly, in that
  Windows Error Reporting's `:443` is not C2. It stopped being hypothetical on
  06 Aug 21:15, when `192.0.2.123:443` landed in `sample_destinations` with
  FakeNet naming `wermgr.exe` at the same address — costing nothing only because
  443 is standard and no domain was notable. Then the same crossed wire produced
  five of nine "VM artifact reads" on 07 Aug 14:53, which is what forced the fix.
  `WINDOWS_RESPONSE_PROCESSES` in `utils` is now the single definition, and both
  passes drop those names *after* lineage resolves them and report what they
  dropped. Replayed against the 21:15 shape: WER's `:443` leaves
  `sample_destinations`, a genuine C2 on a non-standard port survives and still
  raises `unusual_ports`, and the WER requests land in `other_process_requests`
  rather than disappearing.
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
| Split-API YARA rule | **No false positives on real dumps; detection still untested.** 0 matches across 13 live dumps totalling 976 MB on 07 Aug 14:53, and 0 of 120 genuine `Microsoft.NET` assemblies. Its subject was not in memory that run — the parent died before its spawn image could be taken — so nothing has yet confirmed it fires on a dump that does contain stage 2 |
| Windows-response suppression | **Fixed, proven by replay on two real runs.** WER's `:443` leaves `sample_destinations` while a non-standard-port C2 in the same table survives; the 07 Aug 14:53 VM-artifact hits go 9 to 0 with 5 counted as Windows-response. One definition in `utils`, used by both passes, each reporting what it removed. Unproven on a *fresh* run |
| Sysmon highlight lineage | **Proven on a live run**, 07 Aug 14:53 — `other_process_events_excluded: 14`, `high_severity_count: 0`, no `credential_access_or_tampering`, score 70. The `dwm.exe` false positive that moved a band did not recur |
| `activity_observed` | **Proven.** `false` before the fix and `true` after, on the identical sample and chain |
| Crash-as-injection | **Proven.** Fired on the hollowed `RegSvcs`, and moved the verdict a band |
| Crash-dump collection | **Proven**, and produced the payload |
| Adaptive window | **Fired, on the wrong case** — see below |
| Received-file collection | **Root resolution proven**; `received_files.roots` named the real `tools\fakenet\defaultFiles`. The *collection* path is still unproven — nothing has been uploaded since it was written |
| Containment refusal | **Proven** on 06 Aug. Guest armed with `vm_net.ps1 -Arm`, canary launched through the Dynamic Analysis window, and the run refused: `Not contained — a default route reaches the internet through a NAT gateway (Ethernet → 10.0.2.2). The guest is ARMED. The run has not been started.` It named the adapter and gateway and blocked *before* launch. The one time this was previously at stake it failed and malware got through; this time it caught it. Tested with the benign canary, so a failure would have cost nothing |
| Spawn re-dump | **Proven as a mechanism, and it has still revealed nothing.** Fired at t11 on a child first seen at t1, on live Remcos, which drops rather than hollows. On the loader at 3s it fired **not at all**: all three children were skipped `exited before its +3s re-dump`, `RegSvcs` having lived 2.14s. The pairing it was built for was finally produced by *scheduled offsets on the root* instead — see gap 3 |
| Parent-at-spawn dump | **Proven, and its limit is now measured.** 07 Aug 04:41 it recovered an 892 KB assembly present in no other dump — the first artifact here no choice of offsets could have caught. 07 Aug 14:53 it recorded `parent exited before it could be imaged at the spawn of pid 7688` instead, because the root died inside a poll interval of spawning. Roughly half the time on this sample, and no setting changes that: the parent is alive when the child appears or it is not |
| Offsets-pending-at-exit record | **Still correctly silent**, and its sibling fired. The offsets-pending case has never had to report; the parent-exited-at-spawn record fired on 07 Aug 14:53 and is the only reason the missing stage-2 image was explicable rather than a mystery |
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
| Registry-read collection (gap 4b) | **Proven end to end**, 07 Aug 14:53. Procmon accepted the generated `.pmc` (`registry_read: 143,805`), lineage resolved, and the pass produced hits. Volume measured at 2.2x events for 281s total — no teardown blowup. Its first exposure to real data found the false-positive class it needed to: nine hits, all Windows, now suppressed and counted |
| `.pmc` filter rewrite | **Round-trip byte-exact** on `dynamic_default.pmc`, and the generated config re-parses. That the *format model* is right is well evidenced; that **Procmon loads it** is not tested and cannot be on the host. Check the run's `Operation` values before trusting an empty result |
| IL decoder completeness | **Proven structurally**, 09 Aug — 0 undecoded bytes across 61,113 instructions in all 3,697 bodies. This is the right shape of check: an incomplete opcode table cannot reach zero, because an unrecognised opcode's operand decodes to further unrecognised bytes. Before the fix it was silently wrong on every flattened method and nothing said so |
| Proxy-aware call graph | **Proven on the artefact it was built for.** 1,181 of 1,181 bindings have a consumer, and it produced the payload decryptor from a standing start. Unproven on any *other* protected sample — the map locator is generic, but nothing else has been run through it |
| Stage-2 payload decryption | **Proven by the plaintext.** `PE\0\0` at the `e_lfanew` the header itself declares, a coherent section table, and 3.5 KB of header padding decrypting to entropy 0.000. Key recovered algebraically, not searched |
| Native stub emulation | **Drives a no-import stub; has not yet produced a payload.** Carries stage 3 through PEB walk, name resolution, `NtAllocateVirtualMemory`, self-relocation and RC4 decryption that runs to completion. It was twice called a stall and is not one. Do not trust a buffer-watching progress check here — two versions of it gave false answers, the second while being capable of failing, because it watched the allocation while the output went to the stack |

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

**A fourth instance, and the one that shows why a list can never be the
attribution.** The Sysmon highlight pass tested three suppression lists and
treated everything falling through them as the sample's. One of those lists holds
`dwm.exe -> csrss.exe` precisely because Windows compositing raises
`CreateRemoteThread` — and on 07 Aug Sysmon could not resolve the target image, so
the pair was `("dwm.exe", "")`, the allowlist could not match, and the Desktop
Window Manager carried a category that moved the verdict a band. **An unresolved
field defeats a name list, and no amount of extending it fixes that.** Lineage
does not care what the fields say.

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

**Lineage says a process is in the tree; it cannot say the behaviour is the
malware's.** `WerFault` is in the sample's tree because the sample's crash put it there,
and Error Reporting then reads machine identity for its report and tries to upload it.
Attributed by lineage that is a VM check and a C2 contact; both are Windows reacting.
The same is true of anything the OS starts *in response to* the sample — WER, the
indexer noticing a dropped file, a troubleshooter firing after a crash. Lineage remains
the right primitive, and a short list of Windows-response processes belongs in front of
it, counted rather than dropped. One definition, in `utils`, because the VM-artifact pass
and the network attribution both need it and neither imports the other — the sibling-module
rule applied *before* the second instance cost anything, for once.

**A reimplemented PRNG validated on its first output has not been validated.** The
proxy map's keystream starts from a zero state, and `state * state % modulus` is zero
whatever the modulus is — so the first output word was correct while the modulus was
wrong, and only word two diverged. The first token decrypted to a valid Field token and
looked like success. Check a stream cipher against *several* outputs, or against a
structural property of the whole plaintext: "all 1,181 keys are Field tokens" is the
assertion that actually settled it, and it is in `scripts/dotnet_meta.py` as a
pass/fail line rather than left to whoever runs it next.

**An API name in an image is not a statement about the artefact in front of you.**
`na3PRqPuA2` was called AES for two days because an `AesCryptoServiceProvider`
string sat near it and its length divided by 16. Neither is evidence: the string
belongs to the protector's string layer in a different type, and any even buffer
divides by a block size. The rebuilt call graph settled it in one query — the image
holds exactly two decryptors and **neither is reachable from the payload path** — and
the real cipher turned out to be hand-rolled IL with no crypto API at all. *Ask what
reaches the artefact, not what the binary happens to contain.* The same query is the
cheap version of the standing rule about reading one method body before running one
brute force: 792 combinations were spent on the wrong algorithm, not merely the
wrong key.

**Invert the cipher before searching its key space.** The payload cipher subtracts
the *next, still-encrypted* byte, which means it inverts against known plaintext:
one line of algebra over a stock MZ stub returned the key directly, and returned it
*checkable* — printable ASCII repeating with period 10, which a wrong answer is not.
No brute force was run at all. When a routine is short enough to read, read it for a
relation between plaintext and key before treating the key as something to look for.

**A decoder's completeness is testable without knowing what it should say.** The IL
decoder was missing every comparison branch and `endfinally`, so it desynchronised
on precisely the control-flow-flattened methods that mattered, and produced
confident-looking garbage. The check that fixed it needs no ground truth: *count the
bytes the decoder could not name*. Zero across 61,113 instructions is only reachable
if the table is complete, because an unknown opcode's operand decodes to more
unknowns. The two-byte table already carried a comment naming this exact failure;
the one-byte table beside it had the same hole. **When a comment warns about a
failure mode, check the sibling structure for it in the same change.**

**A literal that looks like a key may be there to be guessed at.** Ten
random-looking 16-to-21 character strings sat beside an AES call in the 892 KB stage,
and about 4,000 key derivations were tried against them before the IL showed what they
are for: `ldstr` the literal, `String.get_Length`, `ret`. They are loaded so their
lengths can be taken and discarded. The real key was a byte-array literal initialised
through `RuntimeHelpers::InitializeArray` from `FieldRVA` data, which is where a .NET
key normally lives and which no amount of string guessing reaches. **Read one method
body before running one brute force** — the method body is cheaper and it is the only
thing that answers the question.

**Carve the image, then read it off the box.** The point of recovering a payload
is what static analysis then says about it, and that lives on the host, not in
another detonation. The 07 Aug stage 2 is the strongest instance: `pefile` on the
host produced the forged vendor, the decoy application, the split-fragment
injection API set, the AES resource and its exact block structure — and retracted
two conclusions this document had been asserting, one of which was "there is
nothing more this sample yields". A carved artifact is a question answered on the
bench. `SmartOptimization.dll` was identified — packer, decoy,
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
   strong. The score is descriptive; this is the reasoning. If a Sysmon-driven
   category is in there, check *Sysmon Events From Other Processes* and the
   `Lineage resolved` row before believing it — an event from outside the tree
   carried a whole band once.
5. **Crashes In The Sample's Tree.** A fault outside any mapped module is
   injection evidence, and often the only record of hollowing. Read it together
   with **Virtual-Machine Artifacts The Sample Read** — a crash after a
   guest-additions check is a different run from a crash after nothing. That
   section says `Not Collected` unless the run used
   `dynamic_registry_reads.pmc`, and that is a statement about the config.
6. **Executables The Loader Never Mapped.** Structural, so it works where a
   signature does not: the 05 Aug payload matched no rule in the set and was
   conclusive from its headers. Read the two timestamps side by side — an image
   years newer than the process hosting it did not ship with it — **but a matching
   timestamp proves nothing**, and quietly: stage 3 of `422e30ed…` carries
   `RegSvcs.exe`'s own `0x5ff2b99b`, so on that sample the comparison is defeated by
   construction. The structural findings here do not depend on it. Then read *What
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

**That was true of this 57 KB image and false of the chain, and the difference
matters.** The 892 KB stage recovered on 07 Aug carries the entire injection API
set as UTF-16 literals — split into fragments so that a string search finds
nothing. `'Virtual ' + 'Alloc'`, `'Write ' + 'Process ' + 'Memory'`,
`'kernel ' + '32.dll'`. There *was* something for a signature to key on; it was
in a stage nothing had recovered yet. `tools\yara\local\ringforge_split_api_loader.yar`
now keys on the fragments. See *The 892 KB stage*.

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

### The 07 Aug 14:53 run — gap 4b collected, and every hit was Windows

`run_id 5457f804`, 281s, **224,529** Procmon events, 13 dumps. The tenth run of this
sample, and the first ever to capture a registry read.

**The generated `.pmc` works.** `procmon_filter` records
`dynamic_registry_reads.pmc`, `captures_registry_reads: true`, 18 operations, and
`procmon_summary` shows **`registry_read: 143,805`**. That was the one assumption behind
the whole `.pmc` writer that could not be tested on the host — Procmon accepts a config
this repo generated.

**The volume cost is mild and now measured.** 224,529 events against about 100,000 on
the previous runs, 2.2x — and **281 seconds total**, inside the 252-to-316 band of the
runs before it. The teardown blowup the UPX control made everyone expect did not
happen. A read-capturing run costs roughly double the events and almost nothing in
wall-clock at this window length.

**Gap 4b's finding path fired, and produced nine hits that were all benign.**
74,174 reads by the sample's tree, 69,631 by everything else, and 9 artifacts read:

| Reader | What it read | What it actually is |
|---|---|---|
| `WerFault.exe` (7180) | `SystemManufacturer`, `BIOSVersion`, `SystemProductName`, the BIOS key, `SystemSKU` | Error Reporting collecting machine identity **for its crash report** |
| `powershell.exe` (7688) | `Services\VBoxSF\NetworkProvider` — `name`, `Class`, `ProviderPath` | Windows walking the **network-provider chain**, which any UNC lookup does |

**The sample's own process (5412) and both `RegSvcs` (2932, 9260) read none of them.**
So the answer to gap 4's active question, for this sample, is a **negative**: it does
not check for a VM. That independently corroborates the static finding, where no VM,
sandbox or debugger token appears anywhere in stage 2 in either encoding.

**Two defects, both fixed, and both the same shape.** Lineage says a process belongs to
the sample's tree; it cannot say the *behaviour* belongs to the malware.

- **`WerFault` is Windows reacting to the sample**, not the sample acting. It is in the
  tree because `RegSvcs` spawned it, entirely correctly. `WINDOWS_RESPONSE_PROCESSES`
  now sets those reads aside and counts them. This is the second pass bitten by WER
  lineage — the first is the network-attribution note under *Smaller*.
- **`\services\vboxsf` was too broad.** The `NetworkProvider` subkey is a registration
  Windows enumerates for itself. `ROUTINE_SUBPATH_MARKERS` sets that subkey aside while
  the driver's service key stays a VM check, with a test asserting the narrowing did not
  cost the signal.

Replayed through the fix: **9 hits to 0**, five counted as Windows-response and four as
routine, the note becoming "read none of the known virtual-machine artifacts", and a
synthetic read of `Services\VBoxSF` by the sample itself still firing `vm_specific`.

**Sysmon highlight lineage, proven on a live run.** `other_process_events_excluded: 14`,
`lineage_resolved: true`, `high_severity_count: 0`, and no
`credential_access_or_tampering` — the `dwm.exe` false positive that moved a band did
not recur. Score **70 · Elevated Attention**, `process_injection` strong plus
`scripted_execution`, exactly as the previous nine runs.

**The parent-at-spawn skip record fired for the first time, and it is the only reason
this run is explicable:**

    pid 5412 ... "parent exited before it could be imaged at the spawn of pid 7688"

Dormancy was **+34s**; the root spawned PowerShell and was gone inside one poll
interval. So there is **no 892 KB stage 2 in this run at all** — and therefore the
split-API YARA rule had nothing to match. It scanned 13 dumps totalling 976 MB for **0
matches and 0 false positives**, which is a passed false-positive test rather than a
detection test.

That is the important operational note on `parent-at-spawn`: it worked on the run where
the parent outlived its own spawn and recorded a miss on the run where it did not. The
896 KB image is reachable roughly half the time on this sample, and there is no setting
that changes it — the parent is either alive when the child appears or it is not.

Dormancy across ten runs: **+20, +23, +24, +34, +42, +48, +60s.**

### The 07 Aug 04:41 run — the parent dump paid off, and a band was not earned

`run_id f3d26e46`, 316s, 108,872 Procmon events, 11 of 11 dumps succeeded. The
ninth run of this sample, and the first with `parent-at-spawn` in it.

**A payload no offset has ever caught.** The trigger fired three times — the root
at t36 as it started `powershell.exe`, `RegSvcs` 11164 at t66 as it started
`WerFault`, and `powershell.exe` at t66 as it started `conhost`. In the root's
`_atspawn` image, at `0x5fa0000`:

| | |
|---|---|
| Size | **917,504 bytes** — 11× `SmartOptimization.dll` |
| Type | x86 .NET, `layout: file`, `truncated: false`, `regions_spanned: 1` |
| `TimeDateStamp` | `0x6a7171fc` → 2026-08-04 |
| SHA256 | `e139c422121c32d68424f57e55b410d6c4a40376f4316bd9f2d2b43b77b80a2b` |

**It is in the spawn-moment image and in no other.** The same process's scheduled
dumps report `unmapped: 0` at t1 and `unmapped: 1` at t25, the latter holding only
`SmartOptimization.dll` — whose SHA256 (`7672ecef…`) is identical in the t25 and
t36 images, which is a clean cross-check that the carve is not inventing
anything.

The timestamps place it. The sample carries `0x6a717204`; this image carries
`0x6a7171fc`, **eight seconds earlier**, while `SmartOptimization.dll` is
`0x6a71514c`, about 2.3 hours before that. Three builds in one pipeline, and the
896 KB assembly built eight seconds before the dropper that carries it. **Static
analysis on the host is the next step**, not another detonation.

**And the verdict read 90 · Likely Malicious, which was not earned.** The single
cause: `dwm.exe` raised a `CreateRemoteThread` whose `TargetImage` Sysmon could
not resolve. `_OS_INJECTION_PAIRS` holds `("dwm.exe", "csrss.exe")` for exactly
this case and cannot match `("dwm.exe", "")`, so the event became the run's only
high-severity highlight, `high_severity_count: 1` made
`credential_access_or_tampering` present in its own right, and the score went
70 → 90, Elevated Attention → Likely Malicious, on the Desktop Window Manager
compositing the screen. Replayed through the fix: `high_severity_count` 0, the
category absent, **70 again** — which is what the previous eight runs said.

**The cause was structural and is the fourth instance of one bug.** The highlight
pass tested for the analyzer's tooling, for two exact OS injection pairs and for
noise DNS, and everything falling through those three lists became a finding about
the sample. It had no lineage at all. `summarize_sysmon_events` now takes
`descendant_pids`, judged on the *acting* PID — `SourceProcessId` for events 8 and
10, because reading `ProcessId` there would attribute an injection to the process
injected into. Events from outside the tree go to `other_process_highlights` with
`other_process_events_excluded` and `lineage_resolved` beside them, and the report
lists them under *Sysmon Events From Other Processes*. The `msftconnecttest`
lookups that were sitting in the sample's DNS list are the same hole at low
severity, and go the same way.

**What else this run showed.** Dormancy **+36s**. The two `RegSvcs` were **11
seconds apart** (04:42:29.11 and 04:42:40.27) rather than the 15 ms of every
previous run, and the first died before it could be dumped. Every `RegSvcs` image
again reported `unmapped: 0` — spawn, `_atspawn`, the second `RegSvcs`, and the
crash dump — each with `known_module: 2`, so the zeroes are qualified but
consistent with gap 5's revised reading. The offsets-pending record correctly
stayed **silent**: the root outlived both offsets, so nothing was pending when it
exited. And `procmon_filter` settled the question the previous run could not —
`config_path` named `dynamic_default.pmc` with `captures_registry_reads: false`,
so the `.pmc` writer is not implicated and the field simply had not been switched.
Registry reads uncollected for a third run.

### The 892 KB stage — identified on the bench, 07 Aug

> **The assembly was lost once and re-acquired.** Deleted by hand from `Downloads`
> on 07 Aug, then recovered on the first re-run (`20a9aaf8`, 15:45): dormancy +33s,
> the root outlived its own spawn, and `parent-at-spawn` at t33 held both
> `SmartOptimization.dll` and the 892 KB stage 2. Same SHA256. Even odds per run
> held.
>
> **Then Bitdefender ate three copies of it.** It resumed on its own mid-session
> and deleted the external-drive backup, the working copy and de4dot's cleaned
> output, matching on content rather than extension so `.bin_` gave no protection.
> Only the original export survived. It now lives XOR-wrapped as
> `stage2_assembly_e139c422.xor9` in `G:\ringforge-artifacts\422e30ed_stage2\`,
> with the key and the unwrap snippet in that folder's README. That defeats content
> scanning without an AV exclusion, which is the trade this bench should default to.

### What the resources actually are, and what the recovered key is not

Named from the `ManifestResource` table rather than inferred from size — the
inference is what wasted an afternoon:

| Resource | Size | What |
|---|---|---|
| `StrategyEnumerator.SegmentedInitializer` | 9,448 | the proxy token map |
| `na3PRqPuA2.resources` | 284,891 | **the payload** |
| `InterruptibleInitializer.InitializerCompiler` | 14 | the string table |
| four `.resources` sets | — | WinForms decoys |

**The string table is fourteen bytes.** So the protector's string encryption is
essentially unused in this build, and the `#US` literals already recovered are the
real strings — which is consistent with the injection API fragments sitting there
in clear.

**de4dot reports "Unknown Obfuscator"** but its generic pass still cut the key
builder from 12,448 to 7,730 bytes of IL. Built from source; see the environment
facts for the two workarounds.

**Both opaque predicates are constant**, which defeats the flattening entirely:
`ConfigureVisualEditor()` is `ldnull; ret` and `ResetCompressor()` is
`null == null`. Every branch in the 345-state dispatcher is therefore decidable,
and the builder can be *executed statically* rather than read. Doing that produced:

    key  683c76f39b6f126273b4fec6a679aa5b12d381cc28b221e2d48540f2622118f7
    iv   3ce634d0fa58d49ac80cedbdad63e611

**Those are real and they are the wrong target.** They belong to the fourteen-byte
string-table path and decrypt none of the resources. Worth stating plainly because
the technique is sound — a wrong *target* is a much better position than a wrong
key.

**Where the payload actually hides.** `na3PRqPuA2` is a `.resources` **set**, so it
is read through `ResourceManager.GetObject` and not `GetManifestResourceStream` —
which is why searching for the latter kept finding only protector runtime. That
call is proxy-bound, and nothing calls the proxy wrappers directly either; they sit
behind further proxies.

**DONE, 09 Aug, and it reached the payload.** The inverse index is built, the call
graph is rebuilt, the decryptor is found and `na3PRqPuA2` is decrypted. See *The
call graph, rebuilt* below. The prediction that it would de-obfuscate the whole
assembly's control flow rather than only this question held: one root method,
`#249 BuildModule`, turned out to reach the entire capability set.


The image the parent-at-spawn dump recovered, read with `pefile` on the host. The
most informative artifact this project has produced.

| | |
|---|---|
| SHA256 | `e139c422121c32d68424f57e55b410d6c4a40376f4316bd9f2d2b43b77b80a2b` |
| Size | 892,416 bytes in **file layout**; `SizeOfImage` is 917,504 |
| Type | x86 .NET **DLL** — `_CorDllMain`, `mscoree.dll` its only import, ILONLY + 32BITREQUIRED, metadata `v2.0.50727`, unsigned |
| Compiled | 2026-08-04 05:00:44 UTC — **eight seconds before the dropper** (`0x6a717204`) |
| Forged as | `MemCompress Pro` by `RAMTech Solutions`, "Advanced Windows memory compression and optimization service", v5.3.9.3748 |

Note the size pair: 892,416 is what the carve wrote and what the file on disk
holds, against a `SizeOfImage` of 917,504. That is the file-versus-mapped
distinction working — a payload in file layout, measured against file layout, and
reported complete rather than truncated.

**The decoy is a whole fake application.** 2,675 of 5,499 metadata strings are
generated three-word CamelCase identifiers — 359 begin `Configure`, 359 begin
`Set`, 575 end `Initializer` — under namespaces `MemCompress.Selections`,
`MemCompress_Pro.Compression`, `MemCompress_Pro.UserManagement` and a dozen more.
The WinForms designer resources are real: dialogs with Cancel buttons, a progress
bar, an edit menu with cut/copy/paste/undo/redo bitmaps, a tray icon. The *real*
code is renamed to unicode box-drawing characters and sits alongside the readable
decoy. Same trick as the puzzle game, eleven times the size, and a different
invented identity — `SmartOptimization.dll` forged **Microsoft**, this forges a
plausible third-party utility vendor. The theme, system optimisation, does not
vary.

**The injection engine, in its own strings.** The API names are present as UTF-16
literals, split so a search finds nothing:

`'Virtual ' + 'Alloc'` · `'Write ' + 'Process ' + 'Memory'` ·
`'Open ' + 'Process'` · `'Virtual ' + 'Protect'` · `'Close ' + 'Handle'` ·
`'kernel ' + '32.dll'` · `'Find ' + 'ResourceA'`

reassembled at runtime and resolved with `GetDelegateForFunctionPointer`, which is
how a managed loader calls a native export with no P/Invoke declaration for a
scanner to find. **That is process injection confirmed from the payload's own
contents**, independently of the crash evidence and of the carver.

**And the stage nobody has seen.** One encrypted resource, `na3PRqPuA2`, beside
`System.Security.Cryptography.AesCryptoServiceProvider`:

- **284,673 bytes.** Entropy 7.998, all 256 byte values present with a flat
  histogram. This was read as "1 flag byte + exactly 17,792 AES blocks", and that
  was **wrong** — it is not AES and there is no block structure. 284,672 divides
  by 16 the way any even-sized buffer might, and dividing by the block size of a
  cipher is not evidence that the cipher is in use. See *The call graph, rebuilt*.
- Its resource reader is mscorlib **4.0.0.0** while every decoy UI resource is
  **2.0.0.0**. Two toolchains in one assembly, which is a detectable artifact in
  its own right and is in the rule below.
- A second 9,448-byte blob at entropy 7.979 with no resource-set header is almost
  certainly the encrypted string table, which is why the resource name itself does
  not appear as a literal.

**The key is not recoverable from the strings, and the strings are a trap.** The ten
random `#US` literals were tried as keys — UTF-8 and UTF-16, raw and MD5 and SHA-256,
128/192/256-bit, ECB and CBC with zero and prefix IV, against both `payload[1:]` and
the aligned whole: **792 combinations, no MZ and no printable block.** Then the IL said
why. See *Read at the IL level* below.

**And the deeper reason none of them could ever have worked**: the payload is not
encrypted with AES at all, so every one of those 792 combinations was the wrong
*algorithm*, not merely the wrong key. The `AesCryptoServiceProvider` string that
put AES on the table belongs to the protector's string layer, which sits in a
different type and is never reached from the payload path. **A cryptographic API
name in an image says the image contains that API, not that the artefact in front
of you went through it.** The call graph is what separates those two, and it did.

### Read at the IL level, 07 Aug

This started before there was a decompiler on the host — no ILSpy, no dnSpy, and no
.NET **SDK**, so `dotnet tool install -g ilspycmd` could not run — with a CLR metadata
reader written for the purpose. **That tooling is now `scripts/dotnet_meta.py`**, which
needs only `pefile` and reproduces everything below: heaps, tables, method bodies with
`ldstr` and call targets resolved, `FieldRVA` byte-array literals, managed resources,
and the proxy-map decryption with its own pass/fail self-check. 6,165 methods, 3,697
with bodies, 499 member references resolved to names.

ILSpy 11 was installed afterwards (standalone zip, .NET 10 runtime) and read the
methods the homegrown disassembler could not — anything control-flow flattened.

**An AES-256 key and IV, recovered.** `HandleSender` (method #1357) reads both from
IL byte-array literals through `RuntimeHelpers::InitializeArray`:

| | |
|---|---|
| Key | `f08ba6d11f49945e4039cac609b19afb61491d589bc7983f5b46f66aecc772c7` (field#570 @ rva `0xdb036`) |
| IV | `a8ab71a42a9541649351e3fb3f75365c` (field#577 @ rva `0xdb2d0`) |

`FlushLogger` (#1329) is the cipher factory: `Activator.CreateInstance` of
`AesCryptoServiceProvider` from System.Core 3.5, falling back to 4.0, falling back to
`RijndaelManaged`. `#1435`, which post-processes the plaintext, is a bare `ret`, so
there is no compression or second layer around it.

**But that pair is the *string* decryptor, not the payload's.** Its counterpart
`EnsureSequentialElement` (#1395) encrypts a string and returns
`Convert.ToBase64String`, using a **different** key (field#578) with
`IV = MD5(Unicode(passphrase))` via #1331. Neither configuration decrypts
`na3PRqPuA2`: tried at all 64 start offsets, then every one of 24 candidate keys
against 16 candidate IVs drawn from the field data. No MZ, no printable block.

**The literals that look like keys are inert by design.** This is the part worth
carrying forward. `CoordinateLiteralTracker` (#1336) is three instructions:

    ldstr 'UuDWeaRQUdaGi6K6'
    call  System.String::get_Length
    ret

It loads the string only to return its **length**. `HandleCentralProfile` does the
same with `'FU2kkBL96mt77LxNg3bq'`, discards it, and returns `{1, 2}`. All ten
random literals are loaded and thrown away like this. Roughly 4,000 key guesses were
spent on strings that were placed there to be guessed at — **a 16-character literal
next to an AES call is not evidence of a key, and the cheap check is one method body
rather than one brute force.**

**What the field data says this stage is.** The 16 `FieldRVA` blobs carry more than
the key:

| Field | Contents |
|---|---|
| #568 | **x64 machine code** — `mov rax, imm64` / `cmp [r8+8], rax` / `je` / `mov rax, imm64` / `jmp rax` |
| #580 | **x86 machine code** — `push ebp` / `mov eax,[ebp+0x10]` / `cmp [eax+4], imm32` / `je` / `mov eax, imm32` / `jmp eax` |
| #572 | The MD5 T-table (`d76aa478, e8c7b756, 242070db`…) — a hand-rolled MD5 |
| #574 | The SHA-256 K-table (`428a2f98, 71374491`…) — a hand-rolled SHA-256 |
| #579 | ASN.1 DigestInfo prefix for MD5, OID 1.2.840.113549.2.5 |
| #567, 569, 571, 573, 576, 581 | `Equals`, `GetValueOrDefault`, `get_HasValue`, `ToString`, `get_Value`, `GetHashCode` as UTF-16 byte arrays — reflection lookups |

Two architecture-specific trampoline stubs are the notable pair: a managed assembly
has no ordinary reason to carry raw machine code shaped as compare-then-jump with
placeholder immediates, and carrying both an x86 and an x64 version means it expects
to run in either. That is consistent with inline hooking. **It is not called an AMSI
bypass here, because the string `amsi` does not appear anywhere in the image in
either encoding** — the hook target is unidentified and guessing it would be the same
mistake as the key literals.

**`RecordAutomatedBuilder` (#1335) is not the payload loader** — an earlier version of
this section said it held the payload's framing and key selection, and that was wrong.
ILSpy, once installed, showed it to be the protector's own runtime: it reads a resource
`StrategyEnumerator.SegmentedInitializer`, decrypts it to a `Dictionary<int,int>` of
field token to method token, and binds a delegate to every static field of the
requested type — `Delegate.CreateDelegate` for statics, a `DynamicMethod` with
`Tailcall` for instance methods, bit `0x40000000` selecting `callvirt` over `call`.
That is **proxy-delegate call hiding**, and it is why the call graph looked so thin.

### The proxy map, decrypted

`scripts/dotnet_meta.py --proxy-map` does it. **1,181 bindings, and all 1,181 keys are
valid Field tokens** — which is the self-check: a wrong keystream fails it on the first
pass. Targets split **885 internal** `MethodDef` and **296 external** `MemberRef`, over
266 distinct members. Two independent counts agree that this is the right resource: the
blob is 9,448 bytes, exactly 1,181 × 8, and the assembly holds exactly 1,181 methods
named `ConfigureSortedElement` — the proxy stubs.

**There is no key.** Every constant in the keystream is hardcoded and the state starts
at zero, so the map is computable from the carved image alone.

**What the hidden calls are.** None of this was visible before, because call hiding
strips the tokens from every caller — these are capabilities present in the binary, not
observed behaviour:

| | |
|---|---|
| Download | `WebClient::DownloadFile` |
| Persistence | `RegistryKey::CreateSubKey`, `SetValue` ×2, `OpenSubKey`, `GetValue` |
| File | `File::Copy`, `Exists`, `CreateText`, `WriteAllText`, `Path::GetRandomFileName`, `FileSystemInfo::set_Attributes`, `FileSystemSecurity::AddAccessRule` |
| Process | `Process::Start` ×2 with `ProcessStartInfo` FileName/Arguments/WindowStyle, `GetProcesses`, `GetProcessById`, `get_Id`, `Kill` |
| Native interop | `Marshal::GetDelegateForFunctionPointer`, `AllocHGlobal`, `SizeOf` |
| Reflective load | `Assembly::Load`, `get_EntryPoint`, `ResourceManager::GetObject` |

**Three things that revises.**

- **It is a downloader as well as a carrier.** Gap 1's sample-selection reasoning turns
  on Remcos carrying everything it needs while a downloader stalls in a contained
  guest. This sample has `DownloadFile`, so containment is now a *candidate
  explanation* for why its chain dies — which had not been on the list.
- **Its persistence and drop code demonstrably exist.** "Persistence and dropped files
  sitting at 0 for this sample is a property of the sample" still holds, and now for a
  better reason: the code is present and never reached, rather than absent.
- **`Process::Kill` with `GetProcesses`** is a defence-evasion capability nobody had
  seen on this sample.

**Where the chase stops, and why de4dot is the next tool.** The proxy fields are loaded
by tiny 12-to-25-byte wrapper methods — `PeekExtractor` for `GetObject`,
`ConfigureLiteralResolver` for `Assembly::Load`, `NewRecommender` for `DownloadFile` —
and real code calls those, with 885 internal bindings meaning proxies on proxies. The
string table adds another layer: `RecordInternalAllocator` is control-flow flattened
across 345 dispatcher states, building a 32-byte key and a 16-byte IV one byte per
state, XORing the key against the finished IV, and splicing bytes derived from the
assembly's own identity into the IV. Hand-tracing that is not viable — several indices
are written by multiple states with different values, so the result depends on a path
decided by opaque predicates.

**Decrypting `na3PRqPuA2` was the highest-value open item and it is now closed** —
by the inverse index rather than by de4dot. This paragraph used to say it was
"clearly a deobfuscator's job rather than a decompiler's", and that was the wrong
call: the obstacle was never that the code could not be read, it was that nothing
said *which* code to read. An index over data already in hand answered that. de4dot
was never run against it.

**For gap 4, a weak negative.** No VM, sandbox, debugger, WMI or hardware-identity
token appears anywhere in this image, in either encoding — searched for explicitly.
That is evidence against anti-analysis as the explanation for the deterministic
crash, and it is weak evidence, because both the string table and the payload are
encrypted. **That search has now been run against stage 3 as well, and it holds —
see *Stage 3 carries no anti-analysis primitives* below.**

### The call graph, rebuilt — and the payload decrypted, 09 Aug

The open task from the section above, done. `scripts/dotnet_meta.py --callgraph`.

**The inverse index is the whole trick.** The decrypted map says what each proxy
field *is*; only a scan of every method body says who *uses* it. With both, a
proxy-mediated call is an ordinary edge. The numbers: **1,181 of 1,181 bindings are
loaded, by 785 methods**, giving 7,322 edges over 3,697 bodies. That every single
binding has a consumer is worth as much as the original Field-token self-check —
a map with dangling entries would mean the decode or the scan was incomplete.

**It found the map by itself.** `find_proxy_map` decrypts each candidate resource
and keeps the one whose plaintext is all Field-token keys, rather than keying on
the resource *name*, which is generated per build. The existing self-check is
strong enough to serve as the locator, so nothing here is specific to this sample's
naming.

**First, a decoder bug that had to be fixed before any of it could be trusted.**
The IL decoder was missing the comparison-branch families (`0x2E`–`0x37` short,
`0x3B`–`0x44` long), `endfinally`, `ldsflda`, `ldc.i8`/`ldc.r4`/`ldc.r8` and the
`ldind`/`stind`/`conv.ovf` groups. Every one carries or implies an operand, so each
desynchronised the stream after it — and the flattened methods, which are the ones
worth reading, are exactly the ones full of `beq` and `endfinally`. The module's own
comment on the two-byte table had named this failure mode; the one-byte table had
the same hole. **The check that it is fixed is structural, not a spot check: across
all 3,697 bodies the decoder now leaves 0 undecoded bytes in 61,113 instructions.**
An incomplete table cannot produce that, because an unknown opcode's operand
reliably decodes to more unknowns. Before the fix, three proxy bindings looked
orphaned; they were decode casualties.

**Every wrapper of interest has zero direct callers**, which is what call hiding
buys and why the graph was needed:

| Wrapper | Really calls | Reached from |
|---|---|---|
| `#473 PeekExtractor` | `ResourceManager::GetObject` | `#465 AssembleBuilder` ← `#249` |
| `#407 ConfigureLiteralResolver` | `Assembly::Load` | `#250 AnalyzeSpec` ← `#249` |
| `#408 RateResolver` | `Assembly::get_EntryPoint` | `#250 AnalyzeSpec` ← `#249` |
| `#383 NewRecommender` | `WebClient::DownloadFile` | `#244` ← `#249` |

**One root reaches everything.** `#249 BuildModule` reaches **554 internal methods
and 91 distinct external members** — the entire capability set the proxy map had
only listed. `#250 AnalyzeSpec` is textbook reflective loading, now readable
end to end: `Assembly.Load(<static field 0x400006d>)`, then `EntryPoint`, then
`MethodBase::Invoke(null, args)` with the argument array shaped by whether
`GetParameters()` is empty.

**`#1096` was the trap the graph disarmed.** Two methods reach
`ResourceManager::GetObject`, and the other one lives in
`MemCompress.Mapping.MapperRunner` — the WinForms decoy, fetching dialog bitmaps.
Name-matching alone would have put an afternoon into it. Its declaring type is what
tells them apart.

**Finding the decryptor was a negative result first.** `--xref CreateDecryptor`
returns **two** methods in the whole image, both in
`MemCompress_Pro.Management.EditableManager`, which is the protector's own runtime,
and neither is reachable from `#249`. **There is no cryptographic API on the payload
path at all** — so the decryptor had to be hand-rolled IL. Searching the 554
reachable methods for the *shape* of a byte cipher — arithmetic plus `ldelem.u1` /
`stelem.i1`, no external calls — returned two candidates, and the first was it.

**`#470 ConcatAllocator`**, 92 instructions, no external calls, sitting in the same
type as the resource fetch:

    d[i] = ((d[i] ^ key[i % len(key)]) - d[(i + 1) % len(d)] + 256) % 256

over the array shortened by one, with `key = Encoding.ASCII.GetBytes(arg1)`.

**The key was recovered, not guessed, and this is the part to reuse.** `d[i+1]` is
still ciphertext when byte `i` is written, so the recurrence inverts against known
plaintext: `key[i % klen] = c[i] ^ ((plain[i] + c[i+1]) % 256)`. Run against a stock
MZ/DOS stub, the recovered stream came back **printable ASCII repeating with period
10** — which is the self-check, because a wrong guess is not printable *and*
periodic. The key is **`HREWPjFNAr`**. No brute force was run.

That is the direct counterpart to the standing lesson about the ten decoy literals.
There, roughly 4,000 key derivations were spent on strings placed to be guessed at.
Here the key was never in a string at all, and **one algebraic relation read off the
IL replaced the entire search**.

**What came out.** 284,672 bytes, sha256 `e84f7824…`, kept XOR-wrapped as
`stage3_native_e84f7824.xor9` beside the assembly. It is a **native x86 PE32, not a
managed assembly**: no COM descriptor, no imports at all, a single executable
`.text`, entry point `0x2680`, GUI subsystem. Roughly 7 KB of x86 stub at
`0x1000`–`0x2c00` — ordinary prologues, `rep movsd`, an XOR-then-compare constant
check — and then 272 KB at entropy 7.999, which is its own encrypted stage. **So
this is another loader, and the config and C2 are one layer further down.**

**Byte 0 is asserted, not recovered, and the tool says so.** The cipher's loop guard
is `i <= d.Length`, so a final iteration wraps `i % d.Length` back to zero and
overwrites the byte it had already decrypted. `--decrypt-payload` prints what it
found there (`0xf0`) and sets `M`. Everything else validates on its own: `e_lfanew`
`0xb8` with `PE\0\0` exactly there, the section table coherent with `SizeOfImage`,
and the header padding at `0x200`–`0x1000` decrypting to **100.00% zero**, which is
3.5 KB of plaintext that could not come out right under a wrong key.

**And the first version of that self-check was worthless, which a negative control
caught.** `e_lfanew` sits at bytes 60–63 and `PE\0\0` at 184–187; against a ten-byte
key those exercise key offsets 0–3 and 4–7 and **never touch offsets 8 or 9**, so a
key wrong in its last character passed both cleanly. Exactly the shape of the
standing lesson about validating a reimplemented PRNG on its first output. The
padding run is the check that decides, because it is kilobytes long and therefore
covers every key offset many times over. Running it against deliberately wrong keys
is what made the difference visible — and the numbers are themselves informative:
one wrong key byte leaves the padding **90.01%** zero, which is 1 in 10 and
independently confirms the key length. `--decrypt-payload` now refuses to write
output when the check fails, rather than emitting a plausible-looking file.

**Two things this hands the pipeline, one of them uncomfortable.**

- **Stage 3's `TimeDateStamp` is `0x5ff2b99b` — the same timestamp `RegSvcs.exe`'s
  own header carries.** *Reading a run* says to read the two timestamps side by side
  and treat an image years newer than its host as foreign. On this sample that check
  is defeated by construction, and it is defeated silently. The carver's structural
  findings (`unmapped`, no module covering the range) do not depend on it; the
  timestamp line in the report does.
- **`Assembly::Load` cannot be this resource's consumer**, because a native PE is not
  loadable that way. `#249` also passes the same static field to `#251`/`#248`, and a
  separate root reaches `Marshal::GetDelegateForFunctionPointer` — which, with the
  x86 and x64 trampoline stubs already found in the field data, is the plausible
  execution path. **Which of them actually runs is not established**, and guessing it
  would repeat the mistake this section exists to record.

### Stage 3's inner blob — emulated, partly unpacked, not finished, 09 Aug

Stage 3 is 7 KB of x86 stub plus a 272 KB blob at file offset `0x2c00` — length
`0x42c00`, which is a literal in the entry function's own argument set rather than a
guess, and `0x45800 - 0x42c00` lands exactly on it. **The blob is not recovered.**
What follows is how far it got and precisely where it stopped.

**Static attack: exhausted, and the negative is the useful part.** The blob has flat
byte statistics, **17,088 sixteen-byte blocks with not one repeat**, and no
periodicity at any period up to 192. Repeating-key XOR, additive, subtractive, both
chained-recurrence forms and RC4 were run against a stock MZ/DOS stub over 55
candidate keys drawn from the code constants and the 295-byte gap ahead of the blob.
No MZ from any of them. **The stage-2 trick does not transfer** — there is no simple
keyed transform here to invert, and no amount of further guessing changes that.

**So the stub was emulated instead** — `scripts/emulate_native_stub.py` on Unicorn,
with `scripts/win32_emu_env.py` supplying the process around it. A decryptor does not
have to be understood to be run, which matters because this stub is flattened the same
way stage 2 was, only in machine code: an if-else handler chain behind a dispatcher
that locates its context by scanning the stack for the cookie `0x589dee90`, planted by
the entry function at `0x2701`, and relocates itself via a `call`/`pop` get-EIP at
`0x40117a`. Reversing all of that statically is a much larger job than running it.

What emulation established that static reading had not:

- the stub runs **~5.8M instructions needing no imports at all**, walking the PEB and
  resolving by name from the loader module list
- it calls **`NtAllocateVirtualMemory` directly, never `VirtualAlloc`** — worth
  knowing, because a hook placed on the Win32 name would not see it
- it asks for **`0x457e1` bytes**, copies itself into that allocation and **jumps into
  it**, after which the allocation holds real code including a statically linked CRT
  (`memset`, `strlen`, `wcslen`) and a CRC-32 table builder (`xor eax, 0x4c11db7`,
  256 entries — so a CRC or checksum is part of whatever comes next)
- **it does unpack**: the allocation moves from entropy 7.969 to 7.642 and from
  278,455 to 269,003 non-zero bytes

**It does not stall. That claim was wrong, twice, and the correction is the most
useful thing in this section.** Two successive versions of this document said the
stub stalls — first "is not unpacking at all", then "unpacks and then stops, running
longer will not help". Single-stepping settled it: the loop at `0x40231f` is **RC4
PRGA**, `i = i + 1`, `j = j + S[i]`, swap, keystream byte, with `[ctx+0x60]` counting
bytes against a length in `[ctx+0x90]`. It is 99 instructions per byte, so a 300k
instruction sample covers 3,031 bytes and its single exit branch reads `taken=0` while
being perfectly healthy. Reading the loop's own counter shows it running 3,852 →
4,341 → **13,670 of 13,670, complete**, after which execution moves on.

**Both wrong calls came from the same mistake: watching a buffer nobody had shown was
the one being written.** The check sampled `allocs[0]`, the `NtAllocateVirtualMemory`
region. This RC4 pass writes to a **stack** buffer at `0x2ff040`. So the allocation
holding still was never evidence about progress, and "unchanged" read as a finding
when it was a statement about where the check was pointed. That is the same shape as
`collection_available` in gap 4b, and as the dead path markers: **an instrument aimed
at the wrong place reports absence, and absence looks like an answer.** Measure the
subject's own counter where it has one — the loop had a byte counter in its context
struct the whole time.

**What is actually unknown** is whether the emulation *diverges*. The harness answers
`GetProcAddress` with a `Sleep` stub for every name, claims success from
`VirtualProtect`, and invents a heap handle for `RtlGetProcessHeaps`. Any of those can
steer the code down a path the real thing would not take, silently and without ever
faulting. Logging each API call with arguments and return value, and looking for one
whose answer the code visibly rejects, is the open question — not "why is it stuck".

**And then the hang turned out to be real after all — in a different loop.** The
retraction above is right about `0x40231f`: that RC4 pass completes. It was too broad.
Running 2.4 billion instructions with a scan of every mapped region after each 100M
found no PE and pinned EIP, from the second phase onward, inside `0x2017271`–
`0x2017283` — the CRC-32 loop **in the allocation**, not the RC4 loop in the image.
Both are true at once: RC4 finishes, and the code after it hangs. Single-stepping at
60M instructions caught the first, the original 600M-block run had caught the second.
**Two honest samples of one run at different moments produced two contradictory
headlines** — so say which moment a claim is about.

**What the hang is, measured rather than guessed.** `0x2017291` is
`crc32(buf, len, ctx)`, rebuilding a 256-entry table on the stack every call, which is
why it dominates. Single call site `0x20261e5`; the compare two instructions later is
`cmp eax, [ebp+8]`, so the wanted hash is a **parameter, not an immediate**. Watching
its arguments across 32M instructions: 2,071 calls, **three distinct tuples**, buffer
never moving — hashing `kernel32.dll`, `ntdll.dll` and `stage3.exe` on a cycle. The
last is a name `win32_emu_env.py` invented, which is how the divergence announced
itself.

**Growing the loader list from 3 modules to 23 was a real fix and not the blocker.**
With `RegSvcs.exe` as the image name — what this sample actually hollows — plus twenty
real DLLs, it now hashes all 23, lowercased first, and still matches nothing.

| | |
|---|---|
| Algorithm | CRC-32/MPEG-2: init `0xFFFFFFFF`, non-reflected, poly `0x04C11DB7`, final NOT |
| Parameters | shifts 24 and 8, mask `0xFF`, carried in a ctx struct XORed with `0x4a`, `0xc6`, `0xf5` |
| Verified | reproduces `ntdll.dll` `0x0b4e1ae2`, `kernel32.dll` `0xadedab08`, `user32.dll` `0xc810589c` |
| Wanted | **`0xe11da208`**, identical across all 388 comparisons |

**The wanted hash matches nothing on this machine.** Brute-forced against 4,419 real
filenames from `SysWOW64`, `System32` and `Windows` — ascii and UTF-16LE, with and
without extension, either case. No hit. The constant appears **nowhere** in stage 3's
image or in the allocation, so it is computed at runtime rather than stored.

**Where that leaves it, precisely.** The question is no longer *why does it hang* but
*where does `0xe11da208` come from, and what name was ever going to satisfy it*. The
compare function takes it as an argument, so its caller is the next thing to read.
Note the surrounding code does the same thing with the hash as a literal — **64
distinct `push imm32; call` sites** in the allocation, most into `0x20040a1` — so this
is a whole resolve-by-hash scheme and the stuck lookup is one entry in it.

**Where `0xe11da208` comes from — and the capability set that fell out of asking.**
Walking the frame chain at the compare gives
`0x202ec7e` <- `0x2017051` <- `0x20071be` <- `0x202f00d` <- `0x20309ac` <-
`0x401d2e` <- `0x402a9f`. `0x202ec01` is `get_module_base_by_hash(hash)`: it walks
`PEB->Ldr`, converts each `BaseDllName` to lowercase ascii, CRC-32s it, and returns
`DllBase` on a match or 0 when the list runs out. The hash reaches it from
`0x2017038`:

    push 0xd3 ; push 0x246e8fe6 ; call 0x2004181 ; push eax ; call 0x202ec01

**So the hashes are obfuscated too.** `0x2004181` builds a 20-byte buffer, XORs it
with the per-site key byte and derives the real constant — `decode(0x246e8fe6, 0xd3)
= 0xe11da208`, which is why the value appears nowhere in the image.

**That decoder did not need reversing, only calling.** `scripts/decode_name_hashes.py`
warms the image, finds every `push imm32 ; push imm32 ; call 0x2004181` site and runs
the decoder on each. **45 sites, and 43 decode to names** once matched against a
20,682-entry dictionary built from this host's own `SysWOW64`/`System32` filenames and
export tables. **This is the payload's capability set recovered without unpacking it:**

| | |
|---|---|
| Injection | `NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtGetContextThread`, `NtSetContextThread`, `NtSuspendThread`, `NtResumeThread`, `NtQueueApcThread`, `NtCreateProcessEx`, `NtOpenProcess`, `NtOpenThread` |
| Credentials | **`crypt32!CryptUnprotectData`** (3 sites), `CryptStringToBinaryA` |
| Registry | `NtCreateKey`, `NtSetValueKey`, `NtQueryValueKey`, `NtEnumerateKey`, `NtEnumerateValueKey` |
| File | `NtCreateFile`, `NtWriteFile`, `NtReadFile`, `NtQueryInformationFile`, `NtSetInformationFile`, `NtClose` |
| Token | `NtOpenProcessToken`, `NtQueryInformationToken`, `NtAdjustPrivilegesToken` |
| Recon / control | `NtQuerySystemInformation`, `NtQueryInformationProcess`, `NtQuerySection`, `NtOpenDirectoryObject`, `NtCreateMutant`, `NtDelayExecution`, `NtWaitForSingleObject`, and `explorer.exe` as a hashed process name |

**Two things that names deserve stating plainly.** It is a **direct-ntdll** loader —
every primitive is the `Nt` form, not the kernel32 wrapper, so a hook or monitor on
the Win32 names sees none of it. And `CryptUnprotectData` is **DPAPI credential
theft**; together with `CryptStringToBinaryA` that is the first evidence of what this
chain is actually *for*, after nine detonations that produced only a crash. It is a
capability, not an observation — the same standing caveat as the proxy-map inventory
in stage 2.

**Three hashes match nothing** on this host: `0xe11da208` (the module lookup that
hangs), `0x79dbe71d` and `0x5c4ee455`. A targeted sweep of 226 browser, CRT,
credential-store and LOLBin names across both encodings found none of them, so the
blocker is a name this bench cannot guess. Reading `0x2017038`'s own caller for the
context it expects is the next move, not more guessing — the standing lesson about
brute force and method bodies, one layer up again.

**The hang is fixed, and it was a bug in the harness — a precise, instructive one.**
Sampling the whole frame chain forty times gave **one** chain every time, so the loop
was not above `get_module_base_by_hash`, it was *inside* it. Its termination is:

    mov esi, [esi]            ; next = entry->Flink
    cmp [esi+0x18], eax       ; DllBase == 0 ?
    jne  <loop>               ; keep walking while non-zero

A real `InLoadOrderModuleList` is circular **through a head that lives inside
`PEB_LDR_DATA`**, and that head is not an `LDR_DATA_TABLE_ENTRY` — the bytes at
`head+0x18` are some other field, which reads as zero, and that is how every module
walk in Windows terminates. `win32_emu_env.py` had linked the last entry back to the
*first*, making a pure ring with no sentinel. A walker looking for a module that is
not present then circles forever. **The 2.3 billion instructions were my list, not
their code.** The fix links the last entry's `Flink` to the head, the first entry's
`Blink` likewise, and asserts `head+0x18` reads zero rather than trusting it, since
the whole termination argument rests on that one dword.

**With the list terminated it walks straight past and keeps going**, and the shape of
the remaining work changed completely — from *one unexplained hang* to *implement the
next API*:

| Blocks | Call |
|---|---|
| 5.7M | `NtAllocateVirtualMemory(0xffffffff, …, 0x3000, 0x40)` → the `0x457e1` region |
| 17.2M | `RtlGetProcessHeaps` |
| 24.6M | `RtlDosPathNameToNtPathName_U` |
| 27.1M | **`NtCreateFile(…, access 0x120089, …)`** |
| 33.8M | `RtlFreeHeap` |

**It is opening a file.** That is the first behaviour out of this chain that is not
setup, and it is consistent with the decoded capability set — `CryptUnprotectData`
alongside `NtCreateFile`/`NtReadFile` is a credential store being read. Each further
API implemented moves it one step; the structural obstacle is gone.

**Worth keeping from how this was found.** Three separate wrong calls preceded it —
"not unpacking", "unpacks then stalls", "environment gap or bail" — and every one came
from inferring a cause from an *indirect* signal. What settled it was reading the
loop's own exit condition and then sampling the frame chain, which answered "where is
the loop" in one measurement. The general form, now stated for the third time in this
document: **measure the mechanism, not a proxy for it.**

**Two harness facts that each cost a cycle and will cost the next person the same.**
`UC_X86_REG_FS_BASE` is a **no-op in 32-bit Unicorn** — it accepts the write, reports
no error, and `fs:[0x18]` still faults; FS needs a real GDT descriptor. And a guessed
export-name list is the wrong tool: a name that is not in it resolves to 0 and then
gets *called*, surfacing as `eip 0x0` a long way from the cause. Read the real export
names out of the host's own `SysWOW64\kernel32.dll` and `ntdll.dll` (1,665 and 2,517
names) — free, authoritative, and it removes the whole class of failure.

**A self-check that could not fail, caught by its own output — and then a second one
that could fail and was still pointed at the wrong thing.** The harness first compared
the earliest allocation snapshot against the *last snapshot*; with one snapshot those
are the same sample, so the verdict could only ever read `UNCHANGED`. Fixing that to
compare against the final state made the check *capable* of failing, and it still gave
a false answer, because the buffer it watched was not the one being written. **A check
that can fail is necessary and not sufficient; it also has to be aimed at the
subject.** Both revisions of this section were published before that was noticed.


**A rule that matches where the ruleset matched nothing.**
`tools\yara\local\ringforge_split_api_loader.yar` carries two rules: one on the
split-fragment technique, one on this build. Written `wide`-only, because these are
.NET user strings and `Alloc` and `Handle` also occur 42 and 63 times as *ascii*
inside the generated decoy names — an ascii-or-wide rule would match the padding
and say nothing. No `pe` module, so it works on a process dump.
`"kernel "`, `"32.dll"` and `"Virtual "` are all mandatory rather than counted,
because `"Open "` and `"Close "` in UTF-16 are ordinary UI text that any GUI
process's dump holds. Verified: every string fires on the carved image, and **0 of
120** genuine assemblies under `Microsoft.NET` and `Framework64` match. Not yet
scanned against a real memory dump, which is where a false positive would surface
— the next run puts it against ten to twelve.

### Stage 3 carries no anti-analysis primitives, 09 Aug

Run because gap 4's negative was explicitly weak *while the payload was encrypted*,
and it no longer is. This is the first search of material that was unreadable when
that caveat was written.

**Two searches, because one of them was the wrong tool.** 48 pipeline
`VM_ARTIFACT_MARKERS` plus 64 string tokens over hypervisors, sandboxes, debuggers,
analysis tools and WMI/identity, ascii and UTF-16 — and then, separately, the
*instructions*, because `rdtsc`, `cpuid`, `sidt`, `sgdt`, `sldt` and the VMware
backdoor `in` have **no string form at all** and a token search cannot see them. The
first pass listed `rdtsc` and `cpuid` as strings, which was meaningless.

| Region | Size | Result |
|---|---|---|
| Stage 3 headers | 4 KB | nothing |
| Stage 3 stub (plaintext code) | 6.8 KB | nothing but two `int3` |
| Stage 3 packed blob | 273 KB | **a negative here proves nothing** |
| Emulated allocation (partly unpacked) | 284 KB | nothing above chance |

The stub's only hit is `int3` at `0x40267e`/`0x40267f`, which is the alignment
padding immediately before the entry point at `0x402680`.

**The allocation's apparent hits are decode noise, and there is a control rather
than an assertion.** Linearly disassembling 284 KB of largely still-packed data
produces `in`, `int1` and `int3` constantly — they are one-byte opcodes. Running the
identical scan over the known-random packed blob and over `os.urandom` of the same
length puts every count at or below the baselines: `in` 1,265 against 1,951 and
1,823, `int1` 295 against 495 and 472, `cpuid` 3 against 4 and 2, `rdtsc` 2 against
0 and 1. **A signal that a random buffer reproduces is not a signal** — the same rule
as the carver's eleven unmapped images in an idle Python process.

**What it changes.** Gap 4's negative now covers stage 3's plaintext as well as stage
2's, so "anti-analysis explains the deterministic crash" is worse supported than it
was. It is still **not** conclusive: the 272 KB inner blob is packed and the
allocation only partly unpacked, so this is a stronger bounded negative, not a proof.

**What it does and does not settle for the emulator.** This search was run to choose
between *environment gap* and *anti-emulation bail* as explanations for what looked
like a stall in `emulate_native_stub.py`. The reasoning was sound and the premise was
not: single-stepping then showed there is no stall to explain. The search stands on its
own evidence — no anti-analysis primitive in anything readable — but nothing should be
inferred from it about a stall that does not exist.

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

**That answer was about the 57 KB image, and it is now superseded.** It said the
carved image is a SmartAssembly-protected reflective loader disguised as a puzzle
game with no config in it — all true — and then that "there is nothing more this
sample yields without defeating SmartAssembly, which is a reverse-engineering job
on stage 2."

**Stage 2 has since been recovered, and it is not SmartAssembly-protected.** The
07 Aug run's parent-at-spawn dump produced it, and it uses a different scheme
entirely. So the sample has yielded a great deal more, from a pipeline change
rather than from reverse engineering. See *The 892 KB stage* below for what it is
and what is left in it.

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
