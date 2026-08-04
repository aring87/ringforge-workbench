# Handoff

State of the work, for picking up in a fresh session. `docs/WORKFLOW.md` is the
run procedure; this is what is done, what is known-broken, and what is worth
doing next.

**Last updated:** 2026-08-04 · `main` at `v1.10.0`

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

### 1. Four code paths have never fired on real malware

Persistence hits, dropped files, PowerShell script blocks, and process
injection were all `0` on every run of this session. They may work. So might
the analyzer-attribution filter have, until a sample proved otherwise — that
bug had been silently costing findings on **every run ever performed**, and was
only found because a sample exercised it.

`samples/74eb42416b47c082fc867764b577ceac6f1bd68e192695d79a9e48a7bd3fdd69.zip`
is unanalyzed. A family that drops a payload, installs persistence or injects
would exercise those paths the way AgentTesla exercised the memory and network
ones. **This is the highest-value next step.**

### 2. The score does not discriminate

| Sample | Score | Verdict |
|---|---|---|
| Memory canary (benign) | 24 | Needs Review / Medium |
| mimikatz (packed) | 69 | Needs Review / Medium |
| AgentTesla (live) | 60 | Needs Review / Medium |

`High` requires `>120` and nothing reached it. The verdict field currently
cannot support a decision. This is a usefulness gap rather than a correctness
one, and it is the largest.

### 3. FakeNet's received files are discarded

AgentTesla's exfil report was written to
`tools/fakenet/defaultFiles/FakeNet.html` — it overwrote FakeNet's own default
page — and was found by hand. It is the single most valuable artifact a run
produces and the next revert destroys it. Files FakeNet receives should be
collected into the case directory like every other artifact. Small change.

### 4. The observation window is fixed against variable dormancy

180 seconds, while the same binary sat dormant for 21, 37, 38, 41, 44 and 83
seconds across six runs. A crypter sleeping five minutes produces a clean report
with no indication anything was missed. An adaptive extension — still alive,
nothing spawned yet, keep waiting — would close it.

### Smaller

- No anti-analysis detection. Nothing reports "the sample checked for a VM and
  left."
- Dumps are full 100–160 MB images with no payload reconstruction, which limits
  what can be done with them downstream.
- Two features are correct but **unexercised in the case they exist for**: the
  missed-descendant reconciliation needs a run where the double-spawn recurs
  (it happened in 2 of 6), and `background_network_processes` needs a
  connecting process the noise filter does not already catch. Both correctly
  reported nothing on clean runs.

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
   Was Not Served. Each one means part of the run is unobserved rather than
   quiet.
3. **`Capture` column** on the dumps. `Live (smeared)` qualifies every YARA
   result from that image.
4. **Memory-only rules.** The actual finding on a packed sample.
5. **Spawned vs Background processes.** The first is the sample; the second is
   Windows.

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

Expected on a clean run: 4 dumps all `Frozen`, scheduled offsets matching 0
rules, spawn and exit dumps matching 3, `network_events: 2`, and
`ftp.cyberflor.co` alone in the requested-domains card.
