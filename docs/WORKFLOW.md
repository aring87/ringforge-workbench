# Running a sample, end to end

The operational procedure. Everything here assumes the analysis VM already has
`bootstrap_tools.ps1`, `bootstrap_yara_rules.ps1` and `vm_hygiene.ps1` behind it,
and a `tooling-baseline` snapshot taken from that state.

---

## The short version

```
1.  vm_snapshot.ps1 -Baseline -Force      revert, contained, booted   (host)
2.  copy the sample into samples\                                     (guest)
3.  launch the GUI elevated, detonate                                 (guest)
4.  export the report                                                 (guest)
5.  read network_isolation.level first                                (report)
6.  back to 1 for the next sample
```

Everything below is why each step is there.

---

## 1. Revert first, not last

```powershell
.\scripts\vm_snapshot.ps1 -Baseline -Force
```

Reverting **before** a run rather than after it means the machine you detonate
on is one you have never touched, regardless of how the last session ended --
including sessions that ended badly, or that you did not finish.

That one command does four things in an order that matters:

1. **Powers off hard.** Never a graceful shutdown: asking a machine that has just
   run malware to execute its shutdown path is handing the sample one more
   opportunity, at the moment nobody is watching.
2. **Restores the snapshot.**
3. **Disarms while still powered off.** A snapshot restores the network
   configuration it was captured with, so this is what stops a baseline from
   booting armed. It also means the guest never runs in an armed state at all,
   rather than racing to disarm one that is already up.
4. **Boots and waits** for the guest to report ready.

Reverting discards the guest's `cases\` directory. Export anything you still
want before this step; that is what the prompt is for, and `-Force` skips it.

### If the revert wedges: `restoringsnapshot` with nothing behind it

VBoxManage returns when a state change is **queued**, not done. A manual
`VBoxManage` command issued while a revert is in flight can leave the VM stuck
in a transient state with no process running it — and no VBoxManage command
clears it. `startvm` returns a bare `E_FAIL`.

`vm_snapshot.ps1` waits for the state to settle before each step, so the script
does not cause this. Clicking in the Manager window while it runs still can.

**Tell a wedge from a slow restore before doing anything**, and use read-only
queries — issuing another state change is what caused it:

```powershell
$vbm = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vbm showvminfo "RingForge-Analysis" --machinereadable | Select-String '^VMState='
& $vbm list runningvms
Get-Process VirtualBoxVM,VBoxSVC -ErrorAction SilentlyContinue
```

`VMState="restoringsnapshot"` **with `list runningvms` empty and no
`VirtualBoxVM` process** is a wedge. A genuine restore has a process burning CPU.

**The way out, and it takes every other VM with it:**

```powershell
# 1. Save or power off every other running VM first -- `list runningvms` says
#    which. They will be killed otherwise.
# 2. Close the Manager. VBoxSVC will not die cleanly while a frontend holds it.
Stop-Process -Name VirtualBox -Force
# 3. Then the service. It respawns on the next VBoxManage call.
Stop-Process -Name VBoxSVC -Force
```

Verify with the same read-only query — `VMState` should read `poweroff` or
`aborted` — and check `snapshot <vm> list` still shows the baseline before
reverting again. **Disk images are untouched by this**; it is the service's
in-memory state that was stuck.

Done on 20 Aug against a VM wedged since a revert: state cleared to `poweroff`,
`tooling-baseline` intact. Note `VMStateChangeTime` can keep reporting the stale
moment afterwards — the live `VMState` is the one to believe.

**A `-List` issued while a restore is genuinely in flight can report "No
snapshots".** That is a transient misread, not damage. Do not react to it.

### Replacing the baseline: revert first, and take before you delete

`-Delete` **merges** a snapshot into its parent and `-Take` captures the current
state. Neither reverts anything, so replacing the baseline without reverting
first bakes in whatever is on the disk right now — including the last
detonation.

```
revert  →  make the change  →  TAKE new  →  restore it to verify
        →  delete old  →  rename new into place
```

```powershell
.\scripts\vm_snapshot.ps1 -Baseline -Force              # revert
# ... pull, install, whatever the change is ...
dir cases ; dir samples                                 # hygiene, see below
.\scripts\vm_snapshot.ps1 -Take "tooling-baseline-new"
.\scripts\vm_snapshot.ps1 -Restore "tooling-baseline-new"   # prove it boots
.\scripts\vm_snapshot.ps1 -Delete "tooling-baseline"
VBoxManage snapshot RingForge-Analysis edit "tooling-baseline-new" `
    --name "tooling-baseline"
```

**Take the new snapshot before deleting the old one.** An earlier version of
this section said `-Delete` → `-Take`, and that order leaves **no clean restore
point between the two commands** on a 93.9 GB VM: if the state turns out to be
dirty after the delete, there is nothing to go back to. Taking first, verifying
by restoring it, and only then deleting means every step has somewhere to
retreat to. The rename keeps `-Baseline` and the `-BaselineName` default working
untouched.

This is the order the 16 Aug rebuild actually used; the `-Delete` → `-Take` form
was never run against a real replacement.

**Check for a dirty machine before you take anything:**

```powershell
dir cases ; dir samples
```

`samples\` should hold `mimikatz.exe`, `mimikatz.upx.exe` and
`upx_control.json` and nothing else — a live sample left there is present on
every future revert. `cases\` should not exist. Missing the revert has produced
a post-detonation baseline twice, and both times the only symptom was a stray
`cases\<hash>` folder that someone happened to notice.

**What a stale baseline actually costs**, from the 16 Aug rebuild — the old one
had been restoring all of this on **every revert since roughly 10 Aug**:

- `cases\`, **1.33 GB across 74 files**, including 11 `.dmp` totalling 1,154 MB.
  `case_metadata.json` and `combined_score.json` sat at the case root, which a
  new run for the same sample writes into.
- **`C:\werdumps\RegSvcs.exe.12080.dmp`**. That directory is where
  `crash_evidence.py` looks at the *start* of a run, so every run began with an
  August crash dump in scope.

Export anything in `cases\` before reverting — that run's output exists nowhere
else once the revert lands.

**A `-List` issued while a restore is still in flight can report "No
snapshots".** VBoxManage returns when a state change is *queued*, not done. The
scripts wait for the state to settle; a manual call running alongside one does
not. Do not react to it.

### A `git pull` on the guest does not survive a revert

The guest clone is inside the VM, so a pull is on the disk the snapshot
replaces. Pulling and then reverting leaves the guest on whatever commit the
baseline holds, and the run executes that code with nothing to say so.

This has already cost a run: a detonation done to verify three fixes came back
with the pre-fix behaviour, and only the absence of a new field in
`dynamic_run_summary.json` gave it away.

Either pull **after** the revert and accept losing it next time:

```
revert  →  arm  →  git pull  →  disarm  →  detonate
```

or make it stick by rebuilding the baseline with the pull in it, using the order
above. **Check the commit on the guest before detonating**, whichever you chose:

```powershell
git log -1 --format="%h %s"
```

## 2. Getting the sample in

The VM is contained, so there is no network path in. Options, in order of
preference:

- **Drag and drop / shared clipboard** if Guest Additions provide it.
- **Arm briefly, download, disarm.** Acceptable, but see the warning below.
- **A one-off attached disk image.** Slowest, safest.

If you arm to fetch a sample:

```powershell
.\scripts\vm_net.ps1 -Arm        # host
# ... download in the guest ...
.\scripts\vm_net.ps1 -Disarm     # host
```

**Do not detonate anything in the armed state.** This is now enforced rather
than advised: a run whose guest holds a default route through a hypervisor NAT
gateway is refused before the sample launches, both by the GUI and by the
orchestrator. Setting `allow_uncontained` in the run config overrides it, and
that is deliberately not a checkbox.

It used to be advice only. A deliberate test detonation with the guest armed
produced no prompt, no dialog and no abort — the run emitted one line into the
Output pane and carried on. Worse, `network_isolation.level` reported `ok`,
because it counted default routes rather than asking where they went, and
VirtualBox's NAT gateway is a private address like any other.

Put samples in `samples\`, which is gitignored.

## 3. Detonating

Launch the workbench **elevated** — ProcDump cannot dump without it, and the
preflight will simply report memory capture as unavailable:

```powershell
python scripts\static_triage_gui.py
```

Then **Dynamic Analysis**, set the sample, and confirm the preflight strip before
you start:

| Panel says | Meaning |
|---|---|
| `Mem YARA: ready` | The ruleset compiled; memory scanning will happen |
| ScriptBlock logging enabled | PowerShell script text will be recorded |
| Sysmon running | Injection, image loads and DNS will be seen |

An empty result from a disabled collector looks exactly like a sample that did
nothing. Checking the strip takes five seconds and is the difference between "no
PowerShell was used" and "we were not listening".

**Timeout.** Both memory dumps land at +5s and +25s, so 60 seconds is plenty for
a sample that sits resident. Raise it only for something that stages behaviour
over minutes — installers, droppers with sleep timers.

**Extend if dormant.** On by default, capped at 600 seconds. The timeout above
is the *base* window; if it expires while the sample is still running and
nothing has been seen to spawn, the run keeps waiting in 30-second steps up to
the cap. A sample that has exited, or that has already spawned something, is
never extended — so this costs nothing on a run that went normally.

**The cap is total observation, not extra.** The window starts at the timeout
and grows toward it, so the cap has to clear the sleep you are outlasting with
room to watch what happens next. 600s covers the five-minute evasion sleep this
exists for and leaves five minutes to see the wake. Raise it only with a reason
— a family documented as sleeping longer, or a previous run that ended
`extension_cap_reached` with nothing observed. Past about 900s you are mostly
buying Windows housekeeping.

**Untick it for anything resident.** Both controls, and any sample that sits at
a prompt or idles in-process. The probe cannot tell "alive and waiting for
input" from "asleep and about to unpack", so a resident sample runs to the cap
every time. `mimikatz.upx.exe` did exactly that: 14 extensions, 1148 seconds
against 271 for the same control on a fixed window, with 113,000 Procmon events
to parse instead of 45,000.

What a long window costs, in order:

- **The persistence diffs are the only scored input that scales with it.**
  Tasks, services and autoruns are before/after snapshots, so anything Windows
  installs mid-run can move `suspicious_new_or_modified` and fire the
  persistence category. On the 10-minute control run a full round of idle
  maintenance — NGen, cleanmgr, TrustedInstaller, DISM — left all three at
  zero, so the filters hold, but this is the one to check.
- **LOLBin counts and Procmon volume cannot move a verdict.** They feed only
  the context score, which is capped at 15. They still make the report noisier:
  that run listed seven Windows maintenance LOLBins under Spawned Processes.
- **Teardown grows with the event count**, which is most of the wall-clock cost
  beyond the window itself.

It needs the memory dump watcher to know whether anything has happened. Without
it (not elevated, or ProcDump missing) the window stays fixed and the run
summary records that extension was unavailable rather than pretending the
window was adequate.

If a run ends at the cap with the sample still running and still silent, the
report carries **Observation May Be Incomplete**. Raise the cap and re-run
before reading that result as clean.

**Memory dumps: offsets and the process cap.** Both default to values that suit
a resident sample and can be wrong for a loader.

*Offsets* are seconds after launch at which the whole tree is dumped; blank uses
the profile default of `5, 25`. If the sample exits early, those two can bracket
the only window that mattered. Formbook spawned its hollowing target at +20s and
exited immediately after, so across two runs it was captured once at +5s —
before it had unpacked — and never again. When the previous run's
*Spawned Processes* shows the sample acting at a particular second, put an
offset just before it.

*Max processes* caps how many the watcher will dump. The Formbook chain ran to
six — sample, `powershell.exe`, `conhost.exe`, `RegSvcs.exe`, a second
`RegSvcs.exe`, `WerFault.exe` — and the old cap of five fell on the second
`RegSvcs`, the process most likely to hold the payload. The *Processes Not
Dumped* card names the cap when it is hit; if you see `process cap reached`,
raise it and re-run. The total-size cap is what actually protects the case
directory, and raising the process count only permits more small dumps.

## 4. Export before you revert

Reports land in the case directory inside the guest, which the next revert
destroys. Copy out what you need. The two files worth keeping are the HTML
report and `dynamic_run_summary.json`; the JSON is the one to keep if you only
keep one, since everything in the report derives from it.

**And `network\received\`, when it exists.** Anything the sample uploaded to
the simulated internet is collected there — an exfil report, a stolen-credential
dump, whatever it sent. It is the most valuable artifact a run produces and it
is worth more than the report describing it. The report's *Files Received By
The Simulated Internet* card lists what landed.

**Do not copy `.dmp` files to the host.** They contain the sample's unpacked
payload verbatim — that is the entire point of them — and they are gitignored
for the same reason.

## 5. Reading the result

**Read `network_isolation.level` first, every time.** `ok` now means contained
— it used to mean "exactly one default route exists", which is not the same
thing and let an armed guest report a clean line. `uncontained` blocks the run
outright; `warning` means the run went ahead with something worth knowing about,
such as two adapters or an IPv6 default route.

Each entry in `network_isolation.egress` carries a `reaches` field: `contained`,
`internet`, or `unexpected`. That is the one to look at when the level is not
`ok` — it names which path is the problem.

The GUI's containment line is now re-read immediately before each launch rather
than when the window opened, so it should agree with the summary. The summary
is still the authority.

Then, roughly in order of signal:

| Section | What it means |
|---|---|
| **Matched In Memory But Not On Disk** | The strongest single finding. A payload that was unreadable at rest and became visible once running. |
| **PowerShell Behaviours Observed** | Script text after deobfuscation. An encoded command shows up as what it decoded to. |
| **MITRE ATT&CK** | Techniques with the evidence for each. Absence means not observed, not absent. |
| **Highlights** | Should now contain only the sample's own behaviour. |
| **Spawned Processes** | Analyzer and Windows baseline processes are filtered out. |
| Context sections | Windows baseline, local discovery, non-routable addresses. Deliberately neutral badges — these are not findings. |

**Read the evidence categories, not the score.** The verdict comes from how
many independent kinds of evidence agree — one is Needs Review, one emphatic or
two of any kind is High, three is Likely Malicious. *Evidence Behind The
Verdict* lists which fired. The number is descriptive: activity volume is capped
at 15 points precisely because background noise alone moved a score by nine
points between two runs of the same sample with identical code.

---

## Verifying the pipeline itself

Two controls, both benign, for when a result looks suspiciously empty.

**The canary** (`test_specs\memory_canary\`) proves the memory-versus-disk
comparison works. It builds a marker string at runtime so the literal exists
only in memory. A correct pipeline reports exactly one memory-only rule and
floors severity to Medium on that alone.

**The UPX control** (`test_specs\upx_control\`) proves the *ruleset* covers a
payload compressed at rest, which the canary cannot. Known-good result:

```
disk:        HackTool_Producers
memory-only: HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1
             Powerkatz_DLL_Generic
             mimikatz
```

`samples\mimikatz.upx.exe` is inside the baseline snapshot, so it survives every
revert. If a real sample comes back empty, run this before concluding anything
about the sample.

---

## Real samples

Once the controls pass, the workflow above is the whole procedure. A few things
specific to live malware:

**One sample per revert.** Not negotiable. Without it, run N inherits whatever
run N-1 installed, and the second report quietly describes both.

**Expect the interesting families to be memory-only cases.** AgentTesla, FormBook
and RedLine are the textbook examples: heavily packed at rest, fully readable
once running. They are what the Tier-2 work was built for.

**Check the pre-flight logic still holds.** A rule gated on the `pe` module, on a
magic number at offset 0, or on a small `filesize` bound cannot match a minidump
no matter how good its strings are. `prepare_control.py` explains this for the
UPX control, and the same three disqualifiers apply to any rule you expect to
see in a memory result.

**Budget for the revert.** A full cycle — revert, boot, transfer, detonate,
export — is a few minutes. That is the real throughput limit, not the analysis.

---

## When something looks wrong

| Symptom | First thing to check |
|---|---|
| No memory dumps | Not elevated, or ProcDump missing. See the preflight note. |
| Dumps taken, nothing matched | Run the UPX control. If it passes, the ruleset genuinely does not cover this sample. |
| No PowerShell blocks | Is ScriptBlock logging actually enabled? Disabled looks identical to unused. |
| Findings that are not the sample's | Check `analyzer_events_excluded` and the analyzer counts. Something new may need filtering. |
| Report looks like the last run's | The GUI was already running when you pulled. Python binds modules at import; restart it. |
| Fixes not taking effect | Check the commit you are on in the guest, not just that you pulled. |

That last pair cost two full detonations to diagnose. The reliable way to tell
which code produced a run is to look for the fields a change adds, not the score.
