# UPX positive control

A check that the installed ruleset actually detects a payload that is
compressed at rest -- the one thing the memory canary deliberately does not
test.

## Why this exists

The canary in `test_specs\memory_canary\` proves the mechanism: dumps are
readable, the memory-versus-disk delta is computed, and a memory-only match
raises severity on its own. But it proves it with a hand-written rule from
`tools\yara\local\`, against a string that was never compressed -- only split.

This control asks the question the canary cannot: when a **downloaded**
signature-base rule matches a binary, and that binary is packed so the rule no
longer matches on disk, does the rule come back once the process unpacks itself
in memory?

UPX is the right first packer because it unpacks the whole image at startup, so
even the +5s dump catches a fully reconstructed payload. A packer that unpacks
lazily or in stages would confound "the ruleset does not cover this" with "the
dump was taken too early".

## Candidate

Mimikatz, from the official `gentilkiwi/mimikatz` releases. signature-base
carries several string-based mimikatz rules written for memory scanning, which
is exactly the property this test needs.

Three things independently stop a rule from ever matching a minidump, however
good its strings are, and the pre-flight checks for all of them:

- a condition using the `pe` module, which has no PE to parse in a raw dump
- a magic number anchored at offset 0, almost always `uint16(0) == 0x5a4d`;
  a minidump begins with `MDMP`
- a `filesize` upper bound, usually written as a cheap performance guard with
  no intent to exclude memory, but a dump is orders of magnitude larger than
  the binary the bound was sized for

`Mimikatz_Gen_Strings` carries the last two at once and is the reason this list
exists -- it was predicted as an expectation on the first run and could never
have been met.

Keep it in `samples\`, which is gitignored.

**It is only ever launched, never driven.** The control is about the unpacked
image being present in memory, not about executing any capability, so the
detonation runs `mimikatz.exe` with no arguments and lets it sit at its
interactive prompt. That also happens to be ideal for dumping: it stays resident
through both offsets instead of exiting before the early dump, which is the
failure the canary work ran into repeatedly.

## Preparing the control

Downloading mimikatz and installing UPX both need the guest online, so this part
runs **armed**:

```bash
.\scripts\vm_net.ps1 -Arm
```

In the VM, install UPX (a no-op if it is already there):

```bash
.\scripts\bootstrap_tools.ps1 -AddExclusions -SkipSysmon -SkipWireshark -SkipFakeNet -SkipProcDump
```

Download the x64 mimikatz release by hand into `samples\`. The bootstrap script
deliberately does not fetch it: pulling a credential-dumping tool is a decision
to make per run, not a side effect of installing telemetry tooling.

Then validate the control before spending a detonation on it:

```bash
python test_specs\upx_control\prepare_control.py --sample samples\mimikatz.exe --json samples\upx_control.json
```

That script settles, on disk, every question that would otherwise be
indistinguishable from a broken pipeline afterwards. It confirms the ruleset
detects the candidate unpacked, classifies each matching rule against the three
disqualifiers above, packs the binary, confirms packing destroyed the detection,
and prints the exact set of rules to expect back in memory. It exits non-zero
and says why when the control is not worth detonating.

Filesize bounds are judged against an assumed 50 MB dump. Override with
`--assume-dump-mb` if you are dumping something much larger or smaller.

Then **disarm before running anything**:

```bash
.\scripts\vm_net.ps1 -Disarm
```

Confirm containment from `network_isolation.level` in the run summary, not the
GUI's containment line -- the GUI can still be showing a pre-arm state. Take a
snapshot here, so the post-detonation revert is one step.

## Running it

Detonate `samples\mimikatz.upx.exe` with **Memory dump** and **Memory YARA**
enabled.

## Expected result

| Field | Expected |
| --- | --- |
| Dumps succeeded | 2 or more |
| Rules matching the sample on disk | the packer/stub rules, if any -- not the mimikatz rules |
| Rules only in memory | every rule listed as `expected_memory_only_rules` |
| Severity | High -- three or more memory-only rules make that category strong |
| Verdict | Elevated Attention or worse |

Unlike the canary, this control is expected to clear Medium. Several
independent rules agreeing about a payload that was unreadable at rest is a
stronger claim than one marker string, and the model is meant to say so. A
result of Needs Review here means fewer memory-only rules matched than the
pre-flight predicted -- read the rules table, not the verdict.

## Reading a failure

Because `prepare_control.py` has already eliminated the boring explanations, the
remaining ones are narrow:

| Symptom | Likely cause |
| --- | --- |
| No dumps at all | ProcDump missing or not elevated; check the preflight note |
| Dumps taken, no matches anywhere | The dump is not capturing the unpacked image -- the real finding this test exists to catch |
| Matched in memory *and* on disk | The packed file is not what was detonated; check the path |
| Fewer memory-only rules than expected | Read the rule's condition. If the pre-flight passed it, it found no disqualifier -- so either there is a fourth kind, or the strings genuinely are not in the dump |
| Matched, but severity stayed Low | The severity floor is not being applied |

## Result, 2026-07-30

Passed. `HackTool_Producers` matched on disk both before and after packing, as
predicted -- it keys on version strings in the resource directory, which UPX
leaves intact. `HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1`,
`Powerkatz_DLL_Generic` and `mimikatz` were all destroyed by packing and all
three returned in memory. Score 59, Medium, severity floored by the memory-only
match.

Both dumps matched identically, so the +5s offset alone was sufficient. That
confirms the assumption UPX was chosen for: the image is fully reconstructed
before the original entry point runs.

The run also predicted a fourth rule, `Mimikatz_Gen_Strings`, which could never
have matched. That gap is what the offset-0 and filesize checks now close.

## After this

The next step up is real samples from MalwareBazaar -- AgentTesla, FormBook and
RedLine are the textbook memory-only cases. Those need a snapshot revert between
each, and there is no snapshot automation yet, so budget for that manually.
