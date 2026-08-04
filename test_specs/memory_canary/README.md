# Memory dump self-test

A controlled check that the dynamic run's memory-versus-disk YARA comparison
works, using no malware.

## Why this exists

A real packed sample tests three things at once: whether the dumps are usable,
whether the ruleset covers the unpacked payload, and whether the delta logic
detects it. When such a run comes back empty, it does not say which of the three
failed.

This pair isolates the last one. `canary.ps1` assembles a marker string from two
halves at runtime, so the full literal exists only in the running process's
memory and never in the file. `ringforge_memory_canary.yar` matches that
literal. A correct pipeline therefore reports exactly one rule under "matched in
memory but not on disk".

## Running it

The rule ships in `tools\yara\local\`, which `bootstrap_yara_rules.ps1` installs
into the scanned rules directory on every run, so no manual copying is needed.
Confirm the Dynamic Analysis window reports `Mem YARA: ready`, then run
`test_specs\memory_canary\canary.ps1` as the sample with **Memory dump** and
**Memory YARA** enabled.

## Expected result

| Field | Expected |
| --- | --- |
| Dumps succeeded | 2 or more |
| Rules only in memory | 1 |
| Memory-only rule | `RingForge_Memory_Canary` |
| Rules matching the sample on disk | none |
| Severity | Medium, raised by the severity floor |
| Verdict | Needs Review |

The severity floor is the part worth confirming. One memory-only match is a
single kind of evidence with nothing corroborating it, so it must raise severity
on its own even though this sample does nothing else at all -- and must not go
further than Medium. Both halves matter: a canary that reaches High means the
model has stopped distinguishing one unexplained observation from a finding.

## Reading a failure

| Symptom | Likely cause |
| --- | --- |
| No matches anywhere | Rule not installed; check `tools\yara\rules\local\` exists after bootstrap |
| Matched on disk too | The split assignment in `canary.ps1` was folded into one literal |
| Matched, but severity stayed Low | The severity floor is not being applied |
| No dumps at all | ProcDump missing or not elevated; check the preflight note |

An ascii-only version of the rule matches nothing, because PowerShell holds
strings as UTF-16LE in memory. The shipped rule specifies `ascii wide` for that
reason.

## Scope

This proves the plumbing and the scoring. It says nothing about whether your
ruleset covers real unpacked payloads -- for that, pack a binary the ruleset
already detects, confirm packing breaks the on-disk match, and detonate it.
