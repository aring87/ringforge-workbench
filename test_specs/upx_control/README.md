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
is exactly the property this test needs -- rules gated on the `pe` module cannot
match a raw minidump at all, so they are useless here no matter how good they
are.

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
detects the candidate unpacked, classifies each matching rule as string-based or
`pe`-gated, packs the binary, confirms packing destroyed the detection, and
prints the exact set of rules to expect back in memory. It exits non-zero and
says why when the control is not worth detonating.

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
| Severity | Medium or higher, floored by the memory-only match |
| Verdict | Needs Review or worse |

## Reading a failure

Because `prepare_control.py` has already eliminated the boring explanations, the
remaining ones are narrow:

| Symptom | Likely cause |
| --- | --- |
| No dumps at all | ProcDump missing or not elevated; check the preflight note |
| Dumps taken, no matches anywhere | The dump is not capturing the unpacked image -- the real finding this test exists to catch |
| Matched in memory *and* on disk | The packed file is not what was detonated; check the path |
| Fewer memory-only rules than expected | Partial unpacking, or rules matching a region ProcDump did not include |
| Matched, but severity stayed Low | The severity floor is not being applied |

A run that comes back with the expected rules is the first evidence that the
memory path finds real payloads, not just a canary designed to be found.

## After this

The next step up is real samples from MalwareBazaar -- AgentTesla, FormBook and
RedLine are the textbook memory-only cases. Those need a snapshot revert between
each, and there is no snapshot automation yet, so budget for that manually.
