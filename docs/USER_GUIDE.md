# RingForge Workbench — user guide

**What it does:** you give it a suspicious file, and it tells you what that
file *is*, what it *did*, and how confident it is — with the reasoning shown,
not just a number.

**What makes it different:** most tools give you a score. This one tells you
the difference between *"we looked and found nothing"* and *"we could not
look"*. Those are opposite conclusions and most tools render both as "clean".

You do not need to be a malware analyst to use it. You do need to read the
coverage line before you trust the verdict, and this guide explains why.

---

## Contents

1. [The five-minute version](#the-five-minute-version)
2. [Reading a verdict](#reading-a-verdict)
3. [The six modules](#the-six-modules)
4. [Static analysis, step by step](#static-analysis-step-by-step)
5. [Dynamic analysis, step by step](#dynamic-analysis-step-by-step)
6. [Where your results go](#where-your-results-go)
7. [Using it from the command line](#using-it-from-the-command-line)
8. [Common questions](#common-questions)

Not installed yet? **[INSTALL.md](INSTALL.md)**. Tools missing?
**[TOOL_SETUP.md](TOOL_SETUP.md)**.

---

## The five-minute version

Double-click **`ringforge-gui.exe`**. You get six cards. Click **Open** on
**Static Analysis**, choose a file, run it.

Static analysis does not execute anything. It reads the file: hashes it, parses
its structure, pulls out URLs and IP addresses, scans it with YARA rules, and
asks capa what the code is *capable* of. It is safe to point at anything.

You will get a verdict like this:

```text
band     : No Evidence
severity : Low
verdict  : No Indicators Found
```

or this:

```text
band     : Corroborated
severity : High
verdict  : Elevated Attention
```

or — and this is the one to understand — this:

```text
band     : Nothing Collected
severity : Unknown
verdict  : Insufficient Coverage
```

That last one does not mean the file is clean. It means **the tool could not
see enough to have an opinion**, usually because a collector was missing. Never
read it as a pass.

To actually *run* a sample and watch what it does, you need a virtual machine
and some extra tools — see [dynamic analysis](#dynamic-analysis-step-by-step).
Do not skip that part.

---

## Reading a verdict

Every verdict has three fields that answer different questions.

### The band — how much agreed?

This is the core idea. The workbench does not add up points; it asks **how many
independent categories of evidence pointed the same way.** One tool shouting is
not the same as four quiet tools agreeing.

| Band | What it means |
|---|---|
| **Nothing Collected** | Nothing ran, or everything that ran failed. **No conclusion is possible.** |
| **No Evidence** | Collectors ran and found nothing of concern. |
| **Single Observation** | One thing looked wrong. Nothing else backed it up. |
| **Corroborated** | Several independent categories agreed. |
| **Strongly Corroborated** | Many agreed, including strong indicators. |

**Single Observation is the band people misread.** It is not "a bit
suspicious". It means exactly one signal fired and nothing corroborated it —
which is what both a real detection and a false positive look like at first. It
is an instruction to go and look, not a conclusion.

### The verdict — the sentence

The band translated into plain language. It depends on what was being asked:

| Band | Malware question | Security-posture question |
|---|---|---|
| Nothing Collected | Insufficient Coverage | Insufficient Coverage |
| No Evidence | No Indicators Found | No Weaknesses Found |
| Single Observation | Needs Review | Needs Review |
| Corroborated | Elevated Attention | Multiple Weaknesses |
| Strongly Corroborated | Likely Malicious | Serious Exposure |

Static, dynamic and browser-extension work ask the malware question. API and
spec analysis ask the posture question.

**The No Evidence row has more than one wording, and the difference is the
point.** "Nothing was found" is a weaker claim when something was not looked
at, so the sentence changes to say so:

| You will see | It means |
|---|---|
| **No Indicators Found** | Collectors ran with full coverage and found nothing |
| **No Findings, Coverage Incomplete** | Nothing fired, but a detector was dark. Not a clean bill of health |
| **Benign / Clean Baseline** | Nothing found *and the sample was actually run*. Only available when dynamic analysis contributed |
| **Low Suspicion** | Nothing crossed the bar, but enough accumulated to mention |
| **Findings Not Scored** | Something was seen by a module whose false-positive rate is not calibrated, so it is reported without being scored |

`Benign / Clean Baseline` is the strongest thing this tool will say, and it is
deliberately unavailable to static analysis alone. Reading a file can establish
that nothing was found in it. It cannot establish that nothing happens when you
run it.

### The severity — how bad, if real?

`Low`, `Medium`, `High`, or **`Unknown`**.

`Unknown` is not a middle value. It means the same thing as *Insufficient
Coverage*: nobody knows, because nothing was collected. If you export findings
to a SIEM, `Unknown` deliberately maps to OCSF severity 0 (Unknown) and never
to Informational, so a rule can alert on poor coverage separately from clean
results.

### Coverage — the field to check first

Before the verdict, look at what actually ran:

- **`modules_run`** — which modules contributed
- **`modules_absent`** — which did not
- **`uncollected_categories`** — kinds of evidence nobody could gather

A **No Evidence** verdict with half of `modules_absent` populated is much
weaker than one with full coverage. The band alone cannot tell you that. This
is the single most important habit to build.

---

## The six modules

Each card in the window is a different question. They write into the same case
folder, and **Unified Report** pools them.

### Static Analysis — what is this file?

Reads the file without running it. Hashes, PE and .NET metadata, digital
signature, packer indications, embedded strings, URLs and IPs, YARA matches,
and capa capabilities.

*Safe on any file.* Nothing executes. Start here, always.

### Dynamic Analysis — what does it do?

**Runs the sample** inside an instrumented Windows VM and watches: process
tree, file and registry activity, network traffic, loaded modules, injection,
persistence changes, and memory dumps scanned with YARA.

*Requires a VM you can revert, Administrator, and the tools from
[TOOL_SETUP.md](TOOL_SETUP.md).* This is the one that can hurt you.

### API Analysis — is this endpoint leaking?

Send a request to an HTTP endpoint by hand and have the response scored:
missing security headers, verbose errors, tokens or keys echoed back, data
exposure. Asks the posture question, not the malware one.

### Spec Analysis — is this API design risky?

Point it at an OpenAPI or Swagger definition. It surfaces unauthenticated
endpoints, weak or undocumented auth schemes, and dangerous operations.

### Browser Extension Analysis — what can this extension reach?

Reads a Chrome or Edge extension's manifest and code: permissions, host
access, remote code loading, and obfuscation.

### Unified Report — one answer

Pools every module that ran on a case and bands it **once**, so you get a
single verdict rather than five. This is what you show someone else.

---

## Static analysis, step by step

1. Open **Static Analysis**.
2. **Browse...** and pick a file.
3. Optionally set a case name. Otherwise it is named after the sample.
4. Run it. Steps tick over as they complete.
5. The report opens when it is done.

**What you will see in the report:** an identification section (hashes, type,
signature), what the file is capable of, the strings and network indicators
pulled out of it, any YARA matches with the rule name and where it hit, and the
verdict with its reasoning.

**If capa or FLOSS are missing**, those sections say so rather than appearing
empty. An empty section and a missing section are different claims, and the
report distinguishes them.

### A worked example

Scan something harmless first so you know what normal looks like:

```powershell
.\ringforge.exe scan C:\Windows\System32\notepad.exe --case learning --json
.\ringforge.exe combine cases\learning --pretty
```

Expect **No Evidence / Low / No Indicators Found** — a signed Microsoft binary
with no concerning capabilities. Now you have a baseline for comparison.

---

## Dynamic analysis, step by step

> **Read this before clicking anything.** Dynamic analysis executes the
> sample. Nothing sandboxes it. If you do this on your own computer, you have
> infected your own computer.

### The three rules

1. **A virtual machine you can revert.** Not your workstation. Not a VM you
   care about.
2. **A snapshot taken before the run.** Revert to it between samples. A dirty
   machine makes the next run's before/after comparison meaningless.
3. **Containment you have verified.** Not assumed.

### Before each run

Open **Dynamic Analysis** and read two lines at the top.

**The Telemetry line** lists each collector:

```text
Sysmon: ready | Capture: ready | FakeNet: not installed | Memory: ready
```

`not installed` means that evidence will not be collected, and the verdict will
say so via `uncollected_categories`. Fix it with
[TOOL_SETUP.md](TOOL_SETUP.md) or accept the gap knowingly.

**The containment strip** below it is the important one:

```text
NOT CONTAINED: One IPv4 default route plus an IPv6 default route.
```

If it says that, **stop**. The sample can reach the internet: it can phone
home, pull a second stage, or attack something. It re-reads the network every
four seconds, so it is describing right now — not when you opened the window.

Contain it from the **host**, never inside the guest:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\vm_net.ps1 -Disconnect
```

An adapter disabled inside the guest can be switched back on by anything
running there with administrator rights — including the sample. The hypervisor
is outside its reach.

### Running it

1. Choose the sample.
2. Set a **timeout**. 30 seconds is the default. Loaders often do nothing for a
   while, so **Extend if dormant** keeps watching if nothing happens.
3. Leave **Installer mode** on if the sample looks like an installer — it
   expects a longer, quieter run.
4. **Run Dynamic Analysis** and watch the step list.
5. When it finishes, open **Unified Report**.

### Reading the result

The dynamic report shows the process tree, what was written where, registry
changes, network connections attempted, persistence added, and YARA matches
found in memory that were not on disk — which usually means something unpacked
itself.

**A quiet run is not automatically a clean sample.** Check whether collection
actually happened. A sample that detected your VM and exited does nothing
interesting, and that looks identical to a harmless program until you read the
coverage.

---

## Where your results go

Everything lands in a case folder beside the executable:

```text
cases\<case name>\
    summary.json                 the static result
    combined_verdict.json        the pooled verdict, if you combined
    static_analysis\             hashes, metadata, strings, YARA, capa output
    dynamic_analysis\            Procmon capture, events, Sysmon, packets,
                                 memory dumps, persistence diff, HTML report
    iocs\                        extracted URLs, IPs, domains
```

`combined_verdict.json` is the file to keep. It records not just the verdict
but **what produced it** — the analyzer version, the commit, library versions,
and whether the YARA rule set actually compiled.

> **Case folders are not backed up and not in version control.** If a run
> matters, copy it somewhere before re-running anything into the same case
> name.

---

## Using it from the command line

`ringforge.exe` is for scripting, batches and pipelines.

```powershell
# Scan one file
.\ringforge.exe scan C:\samples\thing.exe --case thing --json

# Pool everything that ran on a case into one verdict
.\ringforge.exe combine cases\thing --pretty

# Read a verdict without rewriting it
.\ringforge.exe combine cases\thing --json --no-write

# Emit the verdict as a SIEM event (OCSF), appended as NDJSON
.\ringforge.exe export cases\thing --spool C:\siem-spool
```

Two flags worth knowing:

- **`--json`** puts machine-readable output on stdout and everything human on
  stderr, so `| ConvertFrom-Json` and `| jq` both work cleanly.
- **`--fail-on BAND`** exits non-zero at or above a band, so a build or a
  gate can act on it:

```powershell
.\ringforge.exe combine cases\thing --fail-on Corroborated
if ($LASTEXITCODE -ne 0) { Write-Output "flagged" }
```

`export` writes a file and nothing else — it never opens a network socket.
Shipping is your forwarder's job, because it is already configured and
monitored for that, and a tool that opens its own socket fails silently when
the SIEM is down.

---

## Common questions

**Is it safe to scan a file with Static Analysis?**
Yes. Nothing is executed. It reads bytes and parses structure.

**Is it safe to use Dynamic Analysis?**
Only in a VM you can revert, contained, with a snapshot taken. It runs the
sample for real.

**Windows says "Windows protected your PC".**
The binary is unsigned. Check the SHA256 against the published hash, then
**More info**, then **Run anyway**.

**My antivirus deleted part of it.**
Expected, and it happens to the tools too — capa and FLOSS are routinely
flagged because of what they are for. Add an exclusion for the install
directory. Inside the VM, `bootstrap_tools.ps1 -AddExclusions` does it for
Defender; on your own machine, do it in whichever product is actually running
there. Behavioural protection is usually a second, separate list that wants
the executable named rather than the folder.

**Everything comes back Insufficient Coverage.**
Collectors are missing. Check the Telemetry line, and `modules_absent` in the
JSON. This is the tool refusing to guess, not a malfunction.

**A verdict says Single Observation. Is it malware?**
Unknown, and that is the honest answer. One signal fired and nothing
corroborated it. Open the report, read which signal, and decide.

**Why did a known-bad sample come back No Evidence?**
Most likely it did not run. Check whether the process actually started and
whether it exited immediately — many samples check for a VM and quit. Also
check `rules_compiled` in the verdict's provenance: if it is zero, your YARA
rule set never loaded and every scan was empty.

**Do I need VirusTotal?**
No. Without `VT_API_KEY` that enrichment reports `skipped` and everything else
works. Note that a lookup tells VirusTotal you have the sample, which can
matter during a live incident.

**Can I run it on Linux or macOS?**
No. It depends on Windows internals and Windows tooling throughout.

**Where do I change settings?**
The GUI saves to `config.json` beside the executable. For scripting, use the
environment variables listed in [INSTALL.md](INSTALL.md).

---

## The one habit worth building

Read the coverage before the verdict.

This tool was built around a specific failure: for a fortnight, a YARA rule set
that had silently failed to compile reported as a clean scan, because the only
number recorded was how many rule *files* were on disk — not how many had
loaded. Every scan in that period said "no matches", and every one of them was
meaningless.

That is why coverage is a first-class field rather than a footnote, why
`Unknown` is not a middle severity, and why *Insufficient Coverage* exists as a
verdict at all. Use them. A confident answer from a tool that could not see is
worse than no answer.
