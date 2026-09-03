# RingForge Workbench

[![Release](https://img.shields.io/badge/release-v1.11.0-blue)](https://github.com/aring87/ringforge-workbench/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://github.com/aring87/ringforge-workbench)
[![Python](https://img.shields.io/badge/python-3.12-yellow)](https://www.python.org/)
[![Analysis](https://img.shields.io/badge/analysis-static%20%7C%20dynamic%20%7C%20api%20%7C%20spec%20%7C%20browser%20extension-orange)](https://github.com/aring87/ringforge-workbench)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)](https://github.com/aring87/ringforge-workbench)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Static insight. Dynamic visibility. API evidence. Structured review.**

RingForge Workbench is a Python/Tkinter software triage workbench for structured static analysis, dynamic behavior review, manual API testing, API specification review, browser extension analysis, and unified reporting from one analyst-facing interface.

It is designed for malware analysts, SOC analysts, detection engineers, and security practitioners who want a practical Windows-focused workflow for reviewing software behavior, organizing case artifacts, and producing consistent analyst-readable reports.

---

## Current Release

| Field | Value |
|---|---|
| Version | `v1.11.0` |
| Release Name | One Verdict Model |
| Release Type | Feature release |
| Platform Focus | Windows analysis environment |
| Language | Python |
| License | MIT |

---

## Project Summary

RingForge Workbench provides a modular case-based workflow for analyzing software samples and related artifacts. It supports static triage, dynamic runtime collection, manual API review, OpenAPI/Swagger specification review, browser extension inspection, and unified reporting.

The workbench emphasizes practical analyst outcomes:

- repeatable case folders
- structured JSON artifacts
- readable HTML/Markdown reports
- one corroboration-based verdict model shared by every module
- baseline/noise reduction
- workflow-specific review screens
- API response review and evidence capture
- case-aware artifact saving
- unified reporting support

---

## Core Capabilities

### Static Analysis

Static Analysis supports Windows executable and package triage, including:

- File hashing
- PE metadata extraction
- LIEF-based enrichment
- Strings review
- capa capability analysis
- IOC extraction
- Signature validation
- VirusTotal enrichment when configured
- Static scoring and verdicting
- API import analysis
- API behavior chain scoring
- Markdown and HTML reporting
- PDF reporting when optional PDF dependencies are available
- Extracted subfile triage
- Subfile scoring and report visibility
- Deep triage warnings and progress visibility

### Dynamic Analysis

Dynamic Analysis supports controlled runtime behavior review inside a Windows analysis VM.

Current dynamic capabilities include:

- Procmon-backed event collection
- Sysmon telemetry: process injection, image loads, WMI persistence, DNS queries, named pipes
- Full packet capture with DNS, TLS SNI, HTTP and connection extraction
- Simulated internet (FakeNet-NG) with per-process connection attribution
- Process memory dumps of the sample's process tree during the run, each target frozen for the duration of its own dump
- Dumps triggered by a descendant appearing and by the root exiting, not only at fixed offsets
- Reconciliation against Sysmon's process tree, so a descendant too short-lived to dump is still reported
- YARA over those dumps, flagging rules that match memory but not the file on disk
- Network containment checking before every run
- Parsed runtime event review
- Interesting event filtering
- Process creation tracking
- Dropped-file summary
- Scheduled task before/after diffing
- Service before/after diffing
- Autoruns before/after persistence diffing
- Installer-aware observation settings
- Post-exit observation for installer handoff behavior
- Cancellation handling with partial summaries
- Dynamic scoring and verdicting
- HTML dynamic report generation
- Capture quality reporting
- Clean baseline checks
- Analyst notes
- Process creates, network connections and DNS lookups attributed to the sample by lineage or by requesting process, with everything else reported as context rather than counted
- Noise filtering for RingForge tools, Procmon, Autorunsc, Windows helper activity, and common clean-baseline behavior
- Windows baseline network traffic separated from sample-attributable indicators
- Explicit warnings when a collector fell back, a lookup went unserved, or the simulated internet could not be reached
- Telemetry coverage reporting, so a missing source is never mistaken for a clean result

### Manual API Tester

The Manual API Tester supports analyst-driven endpoint testing and response review.

Current API testing capabilities include:

- GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS support
- Built-in HTTPBin request presets
- VirusTotal file lookup preset placeholder
- JSON header editing
- JSON or raw body editing
- Multipart file upload testing
- SSL verification toggle
- Timeout configuration
- Response body, headers, and raw response review
- Pretty JSON response formatting
- Response Analysis tab
- Severity Summary counts
- Redacted report mode for safer sharing
- Unredacted full-evidence mode with warning confirmation
- Timestamped default HTML report names
- Active case display
- Open Case API Folder button
- Automatic latest API artifact saving into the active case folder

Manual API Tester case artifacts include:

```text
cases/<case_name>/api_analysis/manual_api_latest.html
cases/<case_name>/api_analysis/manual_api_latest.json
```

### API Specification Analysis

Spec Analysis supports OpenAPI and Swagger-style definition review for local files and direct specification URLs.

Supported inputs include:

- Local `.json`, `.yaml`, and `.yml` OpenAPI/Swagger files
- Direct OpenAPI/Swagger URLs such as `https://petstore3.swagger.io/api/v3/openapi.json`

When a URL is provided, RingForge downloads the specification into the active case folder and analyzes the local copy.

Spec Analysis can help identify:

- Endpoint inventory
- HTTP methods
- Declared authentication schemes such as API key, bearer token, and OAuth2
- Endpoints that do not declare an explicit auth requirement in the spec
- Destructive or update-oriented methods such as `DELETE`, `PUT`, and `PATCH`
- File upload endpoints
- Sensitive-looking parameters
- PII-like schema fields
- Schema quality issues
- Unresolved references
- Notable endpoints for analyst review
- Recommended manual runtime validation tests
- HTML and JSON inventory reports

Spec Analysis findings are treated as review indicators, not confirmed runtime vulnerabilities. The generated recommendations use analyst-focused wording such as:

```text
Validate whether authorization is enforced at runtime, even if the spec does not declare auth.
```

Spec Analysis case artifacts include:

```text
cases/<case_name>/spec_analysis/api_spec_analysis.json
cases/<case_name>/spec_analysis/spec_inventory_latest.html
cases/<case_name>/spec_analysis/spec_inventory_latest.json
cases/<case_name>/spec_analysis/runs/<timestamp>_<spec_name>/
```

### Browser Extension Analysis

Browser Extension Analysis supports static review of Chrome, Edge, and Chromium-style browser extensions.

Supported inputs include:

- Unpacked extension folders
- ZIP extension packages
- CRX packages

Browser extension review includes:

- Manifest parsing
- Permission review
- Host permission review
- Background script and service worker review
- Content script review
- Web-accessible resource review
- File inventory
- File preview
- Risk notes
- Risk scoring
- HTML and JSON export

### Unified Report

The Unified Report module combines available case artifacts into one report.

Supported module summaries include:

- Static Analysis
- Dynamic Analysis
- Manual API Tester
- API Specification Analysis
- Browser Extension Analysis
- Case Verdict

The Unified Report leads with the case verdict, the corroboration behind it and the collection coverage, then the per-module summaries. It uses explicit labels such as `Not run` and `INCOMPLETE` when a module produced no artifacts or a collector did not run — a module that was never run and a module that ran and found nothing are different facts and are reported as such.

---

## Analysis Findings

Seven live samples have been through this workbench end to end. This section is
what the tooling actually produced against each — measurements rather than
claims, with the negatives kept because a negative that was measured is worth
more than a positive that was assumed.

The full working record is in [`docs/HANDOFF.md`](docs/HANDOFF.md) and
[`docs/ROADMAP.md`](docs/ROADMAP.md), including the readings that were later
retracted and why.

---

### Raton — `ce0d08be…` · .NET RAT · **closed**

A commodity RAT whose C2 protocol was driven end to end, from first packet to
the last command in its dispatcher.

| | |
|---|---|
| Family | Raton / SillyRAT, open-source C# RAT (`codeberg.org/Raton/Raton`) |
| Build | **Post-v1.9.0** — the published source dates the sample rather than describing it |
| Persistence | `ONLOGON` scheduled task, self-healing, plus a second `…\CurrentVersion\Run` path |
| C2 | `127.0.0.1:7372`, client speaks first, TLS 1.3, **no certificate validation** |
| Wire format | `0xDEADBEEF` magic, lengths, compression flag, CRC-32, key/value body |
| Beacon | 17.034 s mean, stdev 0.014 — a retry loop, not a heartbeat |
| Capability | 151-case dispatcher; webcam, microphone, HVNC, keylogger, ransom, clipper |
| Detection | 3 YARA rules, benign rate **0 of 13,174** PE files |

**The command channel, driven.** 30 commands sent down one TLS session, 24
answered. An interactive shell, a live SOCKS5 proxy, and a `Compiler` command
that writes an executable to `%Temp%` and runs it — arbitrary code execution
from source text. `Clientinfo` reports the machine's VM identifiers to the
operator, which explains why registry-based VM detection never fired: with no
C2, that collection never runs.

**Three classes of "silent" command, none of them broken:** commands whose
handler switches on a field the dispatcher never reads; commands with a
precondition (`Shell` needs `StartShell`, `ChatMessage` needs `Chat`); and
commands with no reply path at all.

**Attribution.** The family is public source by an author using the aliases
`Silly` / `S-illy`. Three of the four strings originally filed as this
operator's fingerprint turned out to be the vendor's — an unpatched builder
placeholder, a Windows interface GUID, and the author's own Telegram channel
shipped as a config default. The detection rule was renamed accordingly: it
identifies *a build that changed nothing*, not a campaign.

---

### FormBook loader chain — `422e30ed…` · four stages · **open**

The longest-running subject here, and the one that has produced the most
method. Four stages recovered, each by a different technique.

| Stage | What it is | How it was recovered |
|---|---|---|
| 1 | .NET loader, SmartAssembly-protected, forged as a puzzle game | PE carve from process memory |
| 2 | .NET assembly forged as "MemCompress Pro" | Parent-at-spawn dump — present in no other dump |
| 3 | Native x86 loader, no imports, 272 KB encrypted body | Proxy-map call-graph rebuild; key recovered algebraically |
| 4 | **Credential stealer**, 273,408 bytes, no PE header | Emulation through a two-party handshake |

**Stage 4 is a credential stealer** — IE `IntelliForms\Storage2`, Chrome's
`Local State`, Firefox, cookies, autofill — with its strings built on the stack
at runtime, which is why nine detonations found none of them and the ruleset was
never at fault.

**It does not run its stealer, and four explanations for that are eliminated by
measurement:** export tables (bit-identical run with 10,316 names added),
`ApiSetMap` forwarders (never read), a granted host process (it reads the
target's base, sleeps, and returns), and an unreached rendezvous (its caller is
in code nothing branches to). Both routes into the unexecuted two-thirds are
closed: **0 declined branches**, and all **93 indirect calls resolve into
ntdll**.

**Its host-process walk cannot succeed on any machine.** The path builder
produces `C:C:\Windows\System32\<name>` for all twelve candidates, and the real
`CreateProcessW` returns `ERROR_INVALID_NAME` for every one — measured against
the live API, not modelled.

---

### Remcos — `aa4d6427…` · reference case

The first sample to produce a corroborated verdict, and the case the scoring
model is regression-tested against.

| | |
|---|---|
| Chain | Native PE32 → suspended process → remote write → `%APPDATA%\Config\smng.exe` |
| Injection | `CreateProcess` suspended + write + `Set`/`GetThreadContext` |
| Persistence | `HKCU` **and** `HKLM\WOW6432Node` Run keys, value `TRY150-6P1GV6` |
| C2 | `62.60.226.68:24042`, plus `pro.ip-api.com` for geolocation |
| Verdict | 105 · Likely Malicious, three categories present and two strong |

Its expectations were **written down before the run**. Four held, three failed,
and every failure was a pipeline bug rather than a property of the sample — a
run described only afterwards would have read as a clean success.

---

### AgentTesla — `31a762fd…` · fully-worked case

Dormancy, self-spawn, unpack, C2 resolution, FTP authentication and the upload
of its stolen-data report, all captured in a single run.

| | |
|---|---|
| C2 | `ftp.cyberflor.co`, credential `michi@cyberflor.co` |
| Exfil | FTP control `:21`, passive data `:60000-60010` |
| Report format | `Time:/User Name:/Computer Name:/OSFullName:/CPU:/RAM:` then per-credential blocks |
| Verdict | 85 · Likely Malicious |

The uploaded report's format is itself a durable signature — a rule can be
written against the captured upload rather than the binary.

---

### EtherHiding clipper — `af2d8300…` · **closed**

A clipboard hijacker that takes its C2 address from a smart contract.

    .ps1 loader → csc.exe ×2 → hollowed SecurityHealthHost.exe
      → eth_call to a BSC testnet contract, which returns a bare hostname
      → once per second: read the clipboard, report what the victim copied,
        write the C2's reply back into the clipboard

**The C2 controls the clipboard with no validation anywhere in the path.**
Serving a value no one would mistake for a wallet address put that value in the
clipboard 644 times out of 839 rounds, while 593 beacons simultaneously reported
what the victim had actually copied. Whoever controls the C2 controls what lands
in the victim's clipboard.

---

### Dridex — `e30b76f9…` · hollowing proof

Mapped a 102,400-byte image over its own 180,224-byte file at base `0x400000`.
The module-integrity check fired **10 times** across the dumps on identity
(`TimeDateStamp` + `SizeOfImage`) rather than on degree — `modules_compared:
314`, `identical: 314` — which is the exact case its false-negative fix was
made for, and the route that covers the carver's overwrite-in-place blind spot.

---

### `a6a86646…` · the negative that closed a gap

Chosen because it *provably* detects virtualisation — it announces
*"cannot run inside a virtual machine"* in a dialog box. It still reported
`artifacts_read: 0`, with registry, file, device-namespace and WMI routes each
ruled out from its own events.

Two samples for two that provably detect VMs and check by neither registry nor
any other collected route. That is what closed gap 4 by decision rather than
leaving a detector waiting forever for calibration.

---

### What the findings changed in the workbench

Several of the most useful results were about the **instrument**, not the
sample. They are listed because a tool that only ever confirms itself is the
failure mode this project is built against:

- **An emulator that answered file opens by leaf name** silently repaired every
  malformed path a payload built, granting eleven process creations a real
  machine would refuse. Fixed to resolve the path; the walk now creates nothing,
  which is what a real machine does.
- **A hollowing detector lost its finding to a cache eviction**, so whichever
  module crossed the 96-entry limit was graded by degree instead of identity —
  which is how a payload sharing most of its bytes with the file it impersonates
  filed as `identical`.
- **A persistence detector read the wrong key name** and only appeared to work
  because a second collector happened to catch the same task. A false negative
  concealed by redundancy is the exact failure that detector exists to prevent.
- **Analyzer activity was scored as the sample's** four separate times — the
  pipeline's own ProcDump, WerFault, a browser's writes, and Windows Update all
  reached a verdict before lineage attribution was added.
- **A YARA rule's build-specific strings were the vendor's defaults**, so a hit
  meant "an unconfigured build" rather than "the same operator".

Each was found by measurement rather than review, and each is written up with
the reading it replaced.

---

## What's New in v1.11.0

`v1.11.0` replaces five separate scoring systems with one, and the reason is
worth stating plainly: **rewriting them turned up twelve false positives, none
of which produced an error.** Every one produced a result.

### One verdict model

Every module now reports **evidence categories** rather than points, and the
verdict comes from how many independent kinds of evidence agree — not from a
total.

    band                     what it means
    ─────────────────────    ────────────────────────────────────────
    No Evidence              nothing fired
    Single Observation       one category, nothing corroborating it
    Corroborated             two categories, or one emphatic enough
                             to stand alone
    Strongly Corroborated    three categories, or two emphatic ones
    Nothing Collected        no collector ran; nothing can be concluded

The band is what the model computes and it never changes meaning. The **verdict**
is a sentence derived from it, worded for what was actually assessed — a sample
reads `Likely Malicious` where an API specification reads `Serious Exposure`, at
the same severity. Compare cases on the band; the verdict is prose.

The additive model this replaces summed a 0–40 static score, a 0–30 dynamic
score and a spec score, clamped the total to 100, then banded it with thresholds
derived for the 0–40 scale. `MALICIOUS` fired at 30 of 100.

### Absence is not silence

A collector that did not run reports **unknown**, never absent. `capa` with no
ruleset, YARA with no rules directory and a scan that timed out each used to
degrade into a quiet zero that read exactly like a clean sample.

A run whose packer detector was switched off can no longer report a clean
headline, and a case where nothing was collected reports `Insufficient Coverage`
rather than the cleanest verdict the model can express. `Benign / Clean
Baseline` is reserved for a sample that was actually watched running — static
analysis can establish that nothing was found, not that nothing happens.

### What the rewrite found

Each of these was live, silent, and produced results rather than errors:

- **A hash-like filename cost 6 points**, and the pipeline stores samples by
  hash — so every sample it had ever downloaded started six points up.
- **Being unsigned cost 8 points.** Most malware is unsigned and so is most
  small legitimate tooling; the absence of exculpatory evidence is not
  incriminating evidence.
- **An unparseable API specification scored 10 of 30** for having no
  authentication, because the test was `auth_scheme_count == 0` and an empty
  document satisfies it.
- **The browser-extension scorer was saturated.** It added source-pattern points
  once *per file*, so a bundled copy of jQuery reached the top band on `fetch(`
  and `https://` alone. Every non-trivial extension rated `Critical`.
- **The API response analyser's only High finding fired on every endpoint that
  sets a cookie** — every login endpoint an analyst would test.

### Measured against 819 samples

The model above claims a category should fire on malware and not on ordinary
software. That is testable, and none of it had been tested. Four corpora now
exist, each a random sample over the axis that matters, each with its seed
recorded:

    292   Windows System32 executables
    300   Program Files binaries, 55 vendors
    127   MalwareBazaar samples
    100   samples drawn across six years

How often each static category fires:

    category                      Sys32   ProgFiles     family      6-year
    ─────────────────────────    ──────   ─────────   ─────────   ─────────
    stripped_metadata              0.0%        6.0%       77.2%       60.0%
    high_entropy_sections          0.3%        0.0%       35.4%       28.0%
    dangerous_capability *         0.7%        2.4%       25.0%       15.4%
    known_malware_signature        0.7%        0.3%       16.5%       12.0%
    invalid_signature              0.0%        0.0%       15.7%        6.0%
    deceptive_file_identity        0.0%        0.0%        8.7%        7.0%
    obfuscated_managed_code        0.0%        0.0%        4.7%        4.0%
    embedded_network_indicators    8.6%       77.0%       71.7%       67.0%

    * thresholds re-fitted when .NET applications entered the benign
      corpus -- see below

**One of the eight does not work, and it is in the table for that reason.**

`embedded_network_indicators` fires on 77.0% of third-party software and 71.7%
of malware. Containing a URL is a property of software. It is held as context —
reported in full, never counted toward a band.

**`dangerous_capability` was re-fitted because a new corpus showed the old
thresholds were set against the wrong population.** Its benign rates came from
System32 and Program Files, which are overwhelmingly native and, where managed,
overwhelmingly libraries. Measured against 124 benign .NET *applications* it
fired on **17.7%** — four times the published figure, on software the fit had
never seen.

The decision rule did not change; only the corpus did. The original threshold
was argued as *the sensitivity cost is small and it more than halves the
false-positive rate*, and on this corpus that sentence now selects four rather
than three. Moving present from 3 to 4 and emphatic from 5 to 6 costs 4.4 points
of detection and takes the .NET false-positive rate from 17.7% to 8.9%. The row
above is the re-fitted measurement.

The same corpus confirms `obfuscated_managed_code` at 0.0% on all 124, which is
the population that category was built for.

`deceptive_file_identity` had never fired on 819 samples in either direction.
Its three filename predicates are correct and remain unreachable: samples are
acquired by hash, so the authored filename is destroyed before analysis begins.
What rebuilt it was the version block — the claim that *does* survive
acquisition. Thirteen unsigned binaries across the two malware corpora claim to
be Microsoft, three Oracle, one Windows Defender, one Adobe. It now fires on
7.1% and 8.0% of malware and on neither benign corpus.

### The row that was measuring something else

`stripped_metadata` was published at **100% on malware against 10.3% on
third-party software** — the most convincing row in the table. It was measuring
the signature check.

The category asks whether a binary's version-info block names its author. No
collector ever wrote that block. The field was read by the categoriser, produced
by nothing, and constructed by hand only in the tests — which is exactly why
they passed. With the block always empty, the category reduced to *is this
signed by a trusted publisher*: a second copy of `invalid_signature`, and the
double-counting the verdict model exists to prevent. Signing data alone
reproduces the published row to the decimal on all four corpora.

Corrected, it still separates, and better than the false version claimed. The
false-positive rate on third-party software nearly halved, and the reason
reverses the original reading: 7-Zip and GnuWin32 builds carry *complete*
version info and had been firing purely for being unsigned.

**The fix also cost coverage, which is the half worth publishing.** Samples with
no evidence at all went from 0.0% to 19.7% on one malware corpus and 3.0% to
31.0% on the other. 56 samples had been carried by a signal that did not exist.
The rate improved and the module got weaker on the same day, and only one of
those two facts is visible in the table above.

Those 56 were a coherent population rather than a residue: malware carrying
complete, plausible vendor metadata, unsigned. Three categories built against
what the band actually contained — `high_entropy_sections`, the rebuilt
`deceptive_file_identity`, and `obfuscated_managed_code` — recovered 37 of them,
taking the no-evidence share to **1.6% and 17.0%**. Their combined cost across
592 benign binaries is one System32 file moving from *No Evidence* to *Single
Observation*.

Nineteen samples still resist every static category, and that is the number to
compare against — not the 3 the module reported before any of this, which
counted samples covered by a signal that did not exist. Roughly half are .NET
assemblies with entirely readable identifiers: managed code is the module's
largest remaining blind spot, and reading one property of it does not close
that.

**Nothing here was tuned to these numbers.** Each corpus disagreed with the
intuition formed before it, and the corrections are recorded in
`docs/ROADMAP.md` alongside the three collector failures — `strings` never
installed, `capa` missing from a non-activated environment, FLOSS deadlocking —
that each produced a plausible result rather than an error.

### One palette, one stylesheet

The desktop application defined 40 colours and the HTML reports defined 17, and
they shared **none** — which is why the workbench and its own reports read as
different products. There were five report stylesheets in the repository; there
is now one, and both media derive from `design_tokens.py`.

### Supporting changes

- Analysis logic lifted out of two Tkinter windows that had no tests, because
  there was nothing importable to reach.
- `static_triage_engine/scoring.py` reduced from 1,150 lines to 274; what
  remains is the helpers that never had anything to do with scoring.
- The test suite went from 867 with a standing failure to **1081**.

---

## What's New in v1.10.0

`v1.10.0` makes a run say whose behaviour it is describing. Everything the
report attributes to the sample is now decided by process lineage or by the
requesting process, rather than by maintaining a list of everything else that
exists on Windows — and the simulated internet, which had never survived more
than a few seconds of any run, now stays up for the whole observation window.

Validated end to end against a live AgentTesla sample: dormancy, self-spawn,
unpack, C2 resolution, FTP authentication and the upload of its stolen-data
report were all captured in a single run.

### Suspend Before Dump

ProcDump reads hundreds of megabytes while the target keeps running, so a dump
of a live process is a smear rather than a snapshot of any instant. Worse, it
loses payloads: a second-generation process exited mid-read, ProcDump reported
`ERROR_PARTIAL_COPY`, and nothing usable was written.

The target is now frozen for the duration of its dump and resumed in a `finally`
whatever happens, because a leaked suspension would hold the sample frozen for
the rest of the run — a worse outcome than any dump failure it could prevent.

Whether the freeze succeeded is reported per dump as a **Capture** column
reading `Frozen` or `Live (smeared)`. A smeared image is not a failure and is
not filed as one, but a YARA miss against it is weaker evidence than a miss
against a frozen image, and the report now says so rather than leaving the two
looking identical.

### Attribution By Lineage

Filtering background activity by name does not converge. Two runs of the same
control reported entirely different sets — one caught a Group Policy service
host, the next an Intune check-in, OneDrive starting and three Defender console
hosts — because what Windows happens to do during a five-minute window is not a
fixed list.

| Signal | Judged by |
|---|---|
| Process creates | Descent from the sample, seeded on the launched PID *and* anything running the sample's own image, because a dropper relaunching itself is the common shape |
| Network connections | The same descendant set, computed once and shared |
| DNS lookups | The requesting image from Sysmon event 22, since resolution is performed by `svchost` on another process's behalf |

Non-descendants become **context**: reported, but not counted and not scored. A
sample can cause a process it does not parent — through injection, COM, a
service or WMI — so discarding them outright would destroy that evidence with
the same filter that removes the housekeeping. Anything suspicious in its own
right is never demoted, and when the sample cannot be identified at all nothing
is demoted, because "nothing descended from the sample" and "we never
established what the sample was" are the same empty list.

**The sample is no longer mistaken for the analyzer.** `ANALYZER_TOOL_COMMAND_MARKERS`
listed the workbench's own directory names next to precise tool invocations, and
samples live in `samples\` inside that tree exactly as this README prescribes —
so every event involving a sample carried `ringforge-workbench` in its path and
was attributed to us. An AgentTesla run reported zero spawned processes while
the memory dumper was recording the child the sample had just spawned. This had
been true of every run.

### The Simulated Internet Was Never Running

FakeNet answered for about four seconds of every run and then went silent — DNS
and TCP together, its log stopping mid-request, listeners configured and
unreachable. A sample's C2 lookup timed out against a FakeNet that passed every
check the workbench had, and the run reported a clean result.

Its `stderr` was a `subprocess.PIPE` read only in the branch that catches an
immediate exit. Once FakeNet survived the startup grace period nothing drained
it again, and FakeNet echoes every intercepted request including full HTTP
headers — so the OS buffer filled within seconds and the process blocked forever
on its next write. It worked when started by hand only because a console drains
`stderr` continuously, which is why it took five wrong hypotheses to find.

`stderr` now goes to `fakenet.stderr.log` in the run's network folder. A file
cannot fill, and it keeps the diagnostics that would have identified this in one
run instead of five.

| Change | Detail |
|---|---|
| **Listeners** | Reported from the config FakeNet actually loaded, not from log banners. FakeNet 3.5 tags modules by short name, so a healthy run with twelve listeners reported one — `DNS Server`, the only tag containing the word "Server" — while FTP was starting three lines below |
| **Exit code** | Carried, so FakeNet dying mid-run cannot read as success. `STATUS_CONTROL_C_EXIT` is excluded, because that is the shutdown the workbench itself asks for |
| **Served domains** | Split into the sample's and the host's own, so a run does not open with a warning about Windows checking whether it has internet |

### Reporting Honesty

New sections, each rendered only when it has something to say:

| Section | Fires when |
|---|---|
| **Simulated Internet Cannot Be Reached** | The guest holds no default route, so Windows rejects a send before a packet exists and FakeNet has nothing to divert |
| **Name Resolution Was Not Served** | Sysmon recorded the sample resolving a name FakeNet never answered — compared name by name, so Windows' own lookups cannot mask it |
| **Degraded Collection** | A snapshot succeeded only through its fallback. Both task and service collectors reported success while WMI was unreadable, and nothing in the report mentioned it |
| **Descended From The Sample But Never Dumped** | Sysmon recorded a descendant the watcher never saw. One sample created two copies of itself seven milliseconds apart; the second was dumped with three rules matching, the first was never observed |
| **Background Processes / Network** | Ran during the window but not from the sample |

### Supporting Changes

| Change | Detail |
|---|---|
| Path markers | The suppression and detection markers were written `r"\temp\\"` — regex escaping — but matched with a plain substring test, so they asked for two consecutive backslashes and matched no real path. 5/5 user-writable, 13/20 noise and 8/17 analyzer markers were dead, meaning "an executable running from a user-writable location" had never once fired. All fixed together, since enabling detection while leaving the matching suppression dead calibrates worse than either |
| `requirements.txt` | Declares `lief` and `PyYAML`. `step_lief_metadata` runs on every case and feeds `score_risk`, so without lief the score was computed on less evidence; `_load_spec` raises without PyYAML, which is half the accepted OpenAPI formats. lief is pinned at `1.0.0` after checking it against `0.17.4` on a real PE |
| Analyzer tooling | `dumpcap`, `tshark` and the Wireshark directory count as analyzer images. A `CreateRemoteThread` into the workbench's own capture backend was raising T1055 against the sample |
| Windows baseline | `dwm.exe → csrss.exe` injection, `services.exe → svchost.exe -k <group>`, `conhost.exe` as a child, and `MoUsoCoreWorker` from `%WINDIR%\uus\` are recognised. Each check keeps its path and command-line requirements, so a relocated LOLBin or an encoded command line is still reported |
| Baseline domains | `nelreports.net`, `microsoft365.com`, the `.microsoft` gTLD and `microsoftofficehub`. The match is anchored, so `microsoft.com.evil.ru` remains a finding |

---

## What's New in v1.9.0

`v1.9.0` adds process memory dumping and YARA scanning over the result, so a
packed payload can be identified once it is running rather than only guessed at
from the file on disk.

### Process Memory Dumps

Every tier-1 source observes a sample from the outside. None of them can see
what a packer decrypted into its own address space, which is exactly where a
loader that unpacks, runs and exits leaves nothing usable behind.

ProcDump captures the sample's process tree during the observation window.
Unlike the other collectors this cannot be a start-before / stop-after pair,
because a dump is only meaningful while the process is alive, so a watcher
thread runs alongside the detonation.

| Behaviour | Detail |
|---|---|
| **Dump offsets** | Every profile dumps early *and* late — quick `4s, 15s`, standard `5s, 25s`, deep `3s, 20s, 60s`. A loader that exits in a couple of seconds is unreadable by the time its exit is noticed, so a late-only schedule captured nothing at all |
| **Exit trigger** | A root process exiting takes an extra dump of whatever is still alive, in addition to the remaining scheduled offsets rather than instead of them |
| **Process tree** | The launched process plus descendants, tracked continuously so a tree that has already collapsed can still be reported |
| **Guard rails** | 5 processes, 1 GB working set, 4 GB total. Skipped processes are recorded with the reason, so a dump that never happened stays distinguishable from one that found nothing |

ProcDump is used rather than `MiniDumpWriteDump` through ctypes because a 64-bit
process dumping a 32-bit target through the raw API writes a truncated dump that
looks valid and scans badly.

### Memory YARA

The dumps and the sample on disk are scanned in one pass with one compiled
ruleset. The signal this exists for is narrow and specific: **rules that match a
process's memory but not the sample on disk.** That difference is a payload that
was packed, encrypted or downloaded, and it is the one thing static analysis
structurally cannot reach.

Scanning both sides with the same ruleset in the same pass is what makes the
comparison honest — diffing against a separate static run would compare results
produced by whatever rules happened to be installed at the time.

- A memory-only match is one of the evidence categories the verdict is built
  from, and on its own it sets a minimum severity of Medium. Three or more
  distinct memory-only rules make that category *strong*, which reaches High
  without needing anything to corroborate it. Matches present in both memory
  and on disk count as context only, because the static run already reported
  them.
- Match offsets are reported as `dump_file_offset`: byte offsets into the dump
  file, never virtual addresses.
- Rules built on the `pe` module cannot match a raw dump at all, so the report
  states plainly that their absence is not evidence.

### Memory Dump Self-Test

`test_specs/memory_canary/` contains a benign sample that assembles a marker
string at runtime, so the literal exists only in process memory and never in the
file. A correct pipeline reports exactly one memory-only rule and raises severity
to Medium on the strength of that alone.

This isolates the delta logic from ruleset coverage. A packed sample tests the
dumps, the rules and the comparison at once, and when such a run comes back
empty it does not say which of the three failed.

### Supporting Changes

| Change | Detail |
|---|---|
| `scripts/bootstrap_yara_rules.ps1` | New. Installs a YARA ruleset, and test-compiles each file individually so one rule needing an unavailable module is quarantined instead of failing the whole ruleset — `yara.compile` is all-or-nothing across the files it is handed |
| `tools/yara/local/` | Hand-maintained rules that survive a ruleset update, since the downloaded rules directory is rebuilt on every bootstrap |
| `scripts/vm_hygiene.ps1` | New. Disables the browser, Acrobat and OneDrive updaters, MDM enrolment, and Windows Update scanning in the guest, so a run's diffs describe the sample rather than what the machine was going to do anyway. A Chrome update that landed mid-detonation was previously reported as two suspicious autoruns entries, and MDM enrolment retries produced three persistence hits per run. Also reports Defender's posture and any EDR agent present, both of which have to be dealt with before real samples — `-DisableEDR` turns off Defender for Endpoint, which would otherwise upload samples to its tenant |
| Autoruns classification | Startup entries created by the analysis tooling — FakeNet-NG's WinDivert driver, the Procmon and Npcap drivers — are classified separately and excluded from findings and scoring, the same way Windows baseline network traffic already was. They stay listed in the report so the tooling registering correctly is still verifiable |
| `scripts/bootstrap_tools.ps1` | Also installs ProcDump; the preflight check now covers five sources. `-AddExclusions` now covers the temp download directory as well as `tools/`, and falls back to the Group Policy registry when the Defender WMI namespace is missing. `-DisableRealtimeProtection` is available when exclusions are not enough |
| `requirements.txt` | Pins `yara-python`, which was missing entirely — the static YARA path had been silently reporting "not installed" |
| Case folders | The Dynamic Analysis window points the case folder at the selected sample instead of leaving the previous run's folder in place behind a mismatch warning |
| Rounded surfaces | Cards, buttons and badges are drawn from corner arcs and straight edges. The previous smoothed polygon fitted a spline through its corner points, bulging outside its own bounding box and being clipped — which is why outlines had pieces missing |

---

## What's New in v1.8.0

`v1.8.0` added three telemetry sources that cover behaviour Procmon structurally
cannot observe, and rebuilt the interface on a single design system.

### Tier-1 Dynamic Telemetry

Procmon reports filesystem, registry and process IO. It cannot see process
injection, image-load provenance, WMI persistence, DNS resolution, or anything
that crossed the wire. Three sources close those gaps:

| Source | Adds |
|---|---|
| **Sysmon** | CreateRemoteThread injection, process tampering, LSASS credential access, WMI event subscriptions, DNS queries, named pipes, image loads |
| **Packet capture** | DNS answers, HTTP hosts and URIs, TLS SNI, outbound connections, unusual destination ports |
| **FakeNet-NG** | A simulated internet so samples proceed through their real logic, plus per-process connection attribution |

All three are optional. Each degrades to an explanatory status rather than an
exception, and a run proceeds with whatever is available.

Collection is read-only: the Sysmon channel is never cleared. Only events
inside the run window are queried, so a shared analysis VM keeps its history.

### Network Containment

A VM with both host-only and NAT adapters lets a sample bypass the simulated
internet and reach real infrastructure. Nothing in the resulting artifacts
would say so.

Egress paths are now enumerated before the sample is launched. The status log
names every adapter holding a default route, the Dynamic Analysis window shows
a red `NOT CONTAINED` line at rest, and the report carries a containment
warning that caveats the network indicators. IPv6 default routes are detected
separately, since they bypass an IPv4-only redirect.

### Scoring and Reporting Honesty

- **The verdict comes from corroboration, not from the total.** A run produces
  up to seven independent kinds of evidence — a payload only readable in
  memory, process injection, credential access or tampering, persistence
  installed, a suspicious dropped file, contact with a non-baseline
  destination, suspicious PowerShell. One on its own is Medium / Needs Review.
  One that is emphatic in its own right, or two of any kind, is High. Three
  agreeing, or two emphatic, is Likely Malicious.
- **Volume is capped.** Activity counts contribute at most 15 points in total,
  because they are the part that moves between runs: background noise alone
  shifted a score by nine points between two runs of the same control on
  identical code. Noise can colour a verdict; it can never set one.
- A category fires once however many events back it, so one chatty behaviour
  cannot outvote several quiet ones.
- The report lists which categories fired and how each was judged, so the band
  can be checked rather than taken on trust.
- A capture records the whole host, so Windows certificate-revocation,
  telemetry and mDNS traffic is classified as baseline and excluded from
  findings and scoring. Both lists are kept, since C2 does hide behind CDNs.
- Under simulated internet every destination resolves locally, so the domain
  the sample asked for is what counts as contact — not the address it was
  given. Scoring external IPs alone reported a live AgentTesla run, which
  authenticated to its C2 and uploaded stolen data, as having contacted
  nothing.
- **Network evidence is attributed before it is scored.** FakeNet's log and the
  packet capture both record the whole machine, so neither can say what the
  sample did. Domains come from Sysmon's attributed lookups; connections come
  from FakeNet's diverter, which names the requesting process. What the host
  did on its own is counted separately and never scored.
- The diverter also sees connections the capture does not. On the AgentTesla
  run the pcap reported zero unusual ports while the diverter had the sample on
  `:21` and the passive data port `:60009`.
- Telemetry coverage is stated explicitly. If Sysmon was not running, the
  report says so rather than reading as though no injection occurred.
- Absence of a category is recorded as not observed, never as not happened.

### The Observation Window

The window follows the sample rather than a fixed number. One AgentTesla binary
sat dormant for 21, 37, 38, 41, 44 and 83 seconds across six runs of the same
file, so no fixed timeout is right twice.

When the base window expires while the sample is **still running and has not
been seen to spawn anything**, it is extended in steps up to a cap — the only
case where waiting longer can change the result. A sample that has exited, or
that has already acted, has given the run what it came for and is not extended.

Reaching the cap while the sample is still silent is reported as
**Observation May Be Incomplete**, because a sample that sleeps out the window
and a sample that ran and did nothing otherwise produce identical reports.

### Files Received By The Simulated Internet

FakeNet's listeners are real servers rooted at real directories, so a sample
that uploads gets its file written inside the FakeNet installation — outside
the case directory, and destroyed by the next revert. AgentTesla's
stolen-credential report landed on top of FakeNet's own default page and was
found by hand.

Listener roots are snapshotted before launch and anything new *or modified* is
copied into the case directory as a normal artifact, hashed and listed in the
report. Copied, never moved: the roots belong to FakeNet.

### Resilience

- Scheduled task and service snapshots fall back to `schtasks.exe` and
  `sc.exe` when the CIM namespaces are missing, which is common on debloated
  Windows images used as VM bases. A failed snapshot no longer aborts the run.
- Antivirus quarantine of FakeNet-NG is recognised and explained as the
  expected false positive it is.

### Supporting Scripts

| Script | Runs on | Purpose |
|---|---|---|
| `scripts/bootstrap_tools.ps1` | Analysis VM | Installs Sysmon, Wireshark/Npcap, FakeNet-NG, ProcDump and UPX, then verifies with the workbench's own preflight checks |
| `scripts/bootstrap_yara_rules.ps1` | Analysis VM | Installs a YARA ruleset for the memory-versus-disk scan, quarantining rules that fail to compile |
| `scripts/vm_hygiene.ps1` | Analysis VM | Quiets background churn — updaters, MDM tasks, telemetry — and reports what it cannot change |
| `scripts/vm_net.ps1` | Host | Arms and disarms the VM's internet adapter, without a shutdown |
| `scripts/vm_snapshot.ps1` | Host | Takes and restores snapshots, re-establishing containment before the VM boots |

They refuse to run in the wrong place: the guest-side scripts will not install
drivers outside a VM without `-Force`, and the host-side ones explain that
containment and reverting are only enforceable from outside the guest.

The two host-side scripts are the only part of RingForge tied to a specific
hypervisor — see [Hypervisor](#hypervisor).

### Interface Redesign

The six windows each carried their own ttk palette, leaving 183 hex literals
across 11 files and a different look per module. They now share one design
system:

- `gui/theme.py` — design tokens (black and Lexus Ultrasonic Blue Mica 2.0),
  the only file containing colour literals
- `gui/components.py` — canvas-drawn cards, buttons, checkboxes, badges and
  headers, giving Tk rounded corners, hover states and gradients
- `gui/styles.py` — every ttk style declared once

Fixed along the way: card labels rendering on the wrong background, clam
drawing an "✗" for a *checked* checkbox, near-white 3D frames around tables and
notebooks, light focus rings on dark text panes, and white scrollbars that
Windows draws natively regardless of configured colour.

---

## What's New in v1.7.2

`v1.7.2` focuses on API Spec Analysis workflow polish, cleaner spec case organization, direct OpenAPI/Swagger URL support, and better Unified Report integration.

### API Spec Analysis Updates

- Added direct OpenAPI/Swagger URL support.
- Added support for analyzing downloaded spec URLs from the active case folder.
- Standardized API spec outputs under:
  - `spec_analysis\api_spec_analysis.json`
  - `spec_analysis\spec_inventory_latest.html`
  - `spec_analysis\spec_inventory_latest.json`
- Added clean historical run folders under:
  - `spec_analysis\runs\<timestamp>_<spec_name>\`
- Added source-spec preservation under:
  - `spec_analysis\originals\`
  - each historical run folder
- Added downloaded URL source storage under:
  - `spec_analysis\downloaded_specs\`
- Kept compatibility copies for older readers and report paths.
- Improved report wording from **Top Risky Endpoints** to **Notable Endpoints**.
- Improved parser warning language so auth gaps are tied to the specification, not assumed runtime behavior.
- Improved recommended-test wording to emphasize runtime validation instead of declaring vulnerabilities from the spec alone.

### Unified Report Updates

- Added API Spec Analysis summary extraction to the Unified Report.
- Added Spec Score display in the Case Overview section.
- Added API-specific spec-only verdicts such as:
  - `High API Spec Risk`
  - `Medium API Spec Risk`
  - `Low API Spec Risk`
  - `Informational API Spec Review`
- Added API Analysis and Browser Extension Analysis rows to the Unified Report overview.
- Replaced blank score placeholders with clearer labels:
  - `Not generated`
  - `Not run`
- Improved spec-only case reporting so API spec results are not described with malware/dynamic-analysis language.

### Spec Output Layout

New API Spec Analysis output layout:

```text
cases/<case_name>/spec_analysis/
  api_spec_analysis.json
  spec_inventory_latest.html
  spec_inventory_latest.json

  downloaded_specs/
    <downloaded_spec_file>

  metadata/
    api_spec_analysis.json

  originals/
    original_<spec_name>.<ext>

  runs/
    <timestamp>_<spec_name>/
      api_spec_analysis.json
      spec_inventory.html
      spec_inventory.json
      original_<spec_name>.<ext>
```

The latest files stay at the root of `spec_analysis` for quick access and Unified Report integration. Historical runs are kept under `spec_analysis/runs/` to avoid cluttering the main case folder.

---

## What's New in v1.7.1

`v1.7.1` focuses on Manual API Tester improvements, API reporting workflow polish, Unified Report integration, and GUI behavior fixes.

### Manual API Tester Updates

- Added a dedicated **Response Analysis** tab.
- Added automatic API response findings for:
  - HTTP status review
  - HTTPS / cleartext HTTP review
  - JSON / HTML response detection
  - Server header disclosure
  - X-Powered-By disclosure
  - Wildcard CORS detection
  - Set-Cookie observation
  - Missing HSTS observation
  - Verbose error/debug response indicators
  - Token, cookie, credential, or secret-like content detection
- Added **Severity Summary** counts for API findings:
  - High
  - Medium
  - Low
  - Info
- Added **Pretty JSON** formatting for response bodies.
- Added timestamped default names for exported API HTML reports.
- Added **Redact report** mode for safer sharing.
- Added **Unredacted full-evidence report** mode with confirmation warning.
- Added redaction status to exported API reports.
- Added reflected origin/IP redaction for test APIs such as HTTPBin.
- Added active case display inside the Manual API Tester.
- Added **Open Case API Folder** button.
- Added latest Manual API Tester case artifacts:
  - `api_analysis\manual_api_latest.html`
  - `api_analysis\manual_api_latest.json`

### Manual API Tester Reporting Updates

- API HTML reports now include:
  - Method
  - URL
  - Status
  - Response time
  - Content type
  - Response size
  - Redaction status
  - Response analysis
  - Request headers
  - Request body
  - Response body
  - Response headers
  - Raw output
- Exported reports can be saved anywhere the analyst chooses.
- A latest case copy is also saved automatically under the active case folder for Unified Report integration.
- Success popups now explain both save locations:
  - user-selected export path
  - active case API artifact path

### Unified Report Updates

- Integrated Manual API Tester findings into the Unified Report.
- Added API method, URL, HTTP status, content type, response size, redaction status, and response analysis findings to the Unified Report.
- Added latest API HTML/JSON artifact detection.
- Hid empty module sections when no findings are present.
- Improved Unified Report preview formatting.
- Improved generated Manual API Tester Summary formatting.
- Added better formatting for:
  - Analysis findings
  - Severity Summary
  - Notes

### Static/API Scoring Updates

- Wired API import analysis into the static scoring flow.
- Ensured `api_analysis.json` can contribute to static scoring evidence.
- Added support for API analysis scoring in primary sample and subfile flows.
- API scoring remains context-aware so imports and API chains contribute evidence without overpowering the overall verdict.

### GUI Fixes

- Fixed API Tester dialog and messagebox parent behavior.
- Reduced main-window focus jumping when browsing or saving files.
- Improved Manual API Tester response area sizing.
- Stabilized API Tester tab styling so selected tabs highlight without shrinking.
- Added `parent=self` behavior to key browse/save/messagebox actions across relevant windows.

---

## What's New in v1.7

`v1.7` focused on polishing both the static and dynamic analysis workflows. This release improved analyst usability, report clarity, cancellation behavior, installer observation, scoring context, case/output handling, and report naming.

### Static Analysis Updates

- Improved static analysis stability.
- Fixed static cancellation behavior.
- Fixed false static cancellation behavior.
- Improved process-tree cleanup after static runs.
- Advanced settings are now greyed out unless override is enabled.
- Added clearer deep triage warning behavior.
- Added subfile progress visibility.
- Added subfile report section.
- Improved subfile triage presentation.
- Cleaned up VirusTotal status handling.
- Converted PKCS9/TSTInfo parsing noise into a friendlier warning.
- Added sample-specific static report filenames:
  - `<sample>_static_report.html`
  - `<sample>_static_report.md`
- Kept compatibility report copies:
  - `report.html`
  - `report.md`

### Dynamic Analysis Updates

- Added editable observation settings in the Dynamic Analysis window:
  - sample timeout
  - minimum observation seconds
  - post-exit observation seconds
  - installer observation mode
- Added installer-aware post-exit observation so Procmon does not stop too early when installer launchers hand off to child processes.
- Added warning for constrained observation settings.
- Improved dynamic cancellation handling.
- Cancelled runs now write clear partial summaries with:
  - `cancelled: true`
  - `exit_code: -2`
  - `verdict: Cancelled`
  - cancellation reason
- Added timeout explanation for GUI applications that remain open.
- Exit code `-1` is now explained as an observation timeout when appropriate.
- Improved Procmon disabled, missing, skipped, and cancelled states.
- Improved Autorunsc disabled, missing, skipped, and cancelled states.
- Improved dynamic preflight checks.
- Improved dynamic progress/status messages.
- Added case/output folder synchronization to reduce cross-case result mixups.
- Added sample-specific dynamic report filenames:
  - `<sample>_dynamic_report.html`
- Kept compatibility report copy:
  - `dynamic_report.html`

### Dynamic Reporting Improvements

- Improved Capture Configuration / Tool Status section.
- Added timeout, minimum observation, post-exit observation, installer mode, and capture quality to reports.
- Improved cancelled and partial dynamic run reporting.
- Improved Autoruns report readability.
- Improved Spawned Processes table readability.
- Improved Suspicious Path Hits and Persistence Hits table readability.
- Improved report layout and column sizing.
- Improved clean-baseline reporting for Notepad-style GUI applications.
- Improved installer context notes for installer/helper behavior.

### Scoring and Noise Reduction

- Improved installer-aware dynamic scoring.
- Reduced false positives from normal Windows service state changes.
- Reduced noise from RingForge-generated files and dynamic run metadata.
- Reduced Procmon/Autorunsc/RingForge tool noise.
- Reduced clean baseline noise from Windows helper behavior.
- Improved Wireshark/Npcap installer context handling.
- Improved interpretation of installer helper processes and LOLBin-like activity in context.

---

## Validation Summary

`v1.9.0` was validated by repeated live detonations in a VirtualBox Windows 11
analysis VM with all six sources active, under confirmed containment
(`network_isolation` reporting no default route).

Verified end to end:

- ProcDump capture of the launched process and of surviving children, with both
  the scheduled and exit triggers firing in the same run
- YARA scanning of 230–320 MB dumps against 550 rule files, at roughly five
  seconds per dump
- The memory-versus-disk comparison, using the `memory_canary` self-test: no
  match against the file on disk, one memory-only rule, and severity raised from
  Low to Medium by that finding alone
- ProcDump returning a non-zero exit code on a *successful* dump, confirming that
  the written artifact rather than the exit code has to be the success signal
- Scheduled task and service CIM fallbacks reporting `fallback_used` on a
  debloated image

`v1.8.0` was validated by repeated live detonations with Procmon, Sysmon, packet
capture and FakeNet-NG active.

Verified end to end:

- Packet capture start, clean stop, and parsing of real DNS, HTTP and TLS
  traffic, across multiple interfaces
- FakeNet-NG lifecycle and log parsing against real FakeNet output, including
  per-process connection attribution
- Network containment detection on a two-adapter VM, and on a contained VM
  with no default route
- Scheduled task and service snapshot fallbacks against a VM whose
  `Root\Microsoft\Windows\TaskScheduler` CIM namespace is absent
- Graceful degradation for every tool when it is not installed
- Report rendering for populated, degraded and legacy summaries
- Scoring calibration: baseline-only network traffic scores lower, while an
  injected C2 domain, URL and IP still surface and score above it
- Sysmon collection against a live channel holding 53,000+ records spanning
  two weeks, confirming both the newest-first read and the parsing of
  `wevtutil`'s single-quoted XML

A final detonation reported all four sources as `Collected`, with Sysmon
returning process creation and registry events for the run window.

`v1.7.2` was validated with API Spec Analysis and Unified Report workflows.

Validated Spec Analysis checks:

- Risky local OpenAPI YAML test
- Lower-risk local OpenAPI YAML test
- Public Swagger Petstore OpenAPI JSON test
- Direct URL input test using `https://petstore3.swagger.io/api/v3/openapi.json`
- Downloaded spec storage under `spec_analysis\downloaded_specs\`
- Latest spec report opening from `spec_inventory_latest.html`
- Historical run folder creation under `spec_analysis\runs\`
- Source spec preservation under `spec_analysis\originals\`
- Unified Report Spec Analysis artifact detection
- Unified Report Spec Score display
- Unified Report API-specific verdict display
- Unified Report `Not run` and `Not generated` labels for missing modules

Expected API Spec Analysis artifact output:

```text
cases/<case_name>/spec_analysis/api_spec_analysis.json
cases/<case_name>/spec_analysis/spec_inventory_latest.html
cases/<case_name>/spec_analysis/spec_inventory_latest.json
cases/<case_name>/spec_analysis/runs/<timestamp>_<spec_name>/api_spec_analysis.json
cases/<case_name>/spec_analysis/runs/<timestamp>_<spec_name>/spec_inventory.html
cases/<case_name>/spec_analysis/runs/<timestamp>_<spec_name>/spec_inventory.json
```

Expected API Spec Analysis Summary fields in Unified Report:

```text
Spec title: <spec title>
Spec version: <version>
Spec type: openapi
Format: json or yaml
Parser confidence: high
Endpoints: <count>
Unauthenticated endpoints: <count>
Sensitive unauthenticated endpoints: <count>
High-risk endpoints: <count>
Medium-risk endpoints: <count>
Schema issue endpoints: <count>
File upload endpoints: <count>
Auth gap count: <count>
Auth schemes: <schemes>
Risk notes:
Notable endpoints:
```

`v1.7.1` was validated with Manual API Tester and Unified Report workflows.

Validated API workflow checks:

- HTTPBin GET request test
- HTTPBin reflected header test
- Redacted report export
- Unredacted full-evidence report export
- Redaction warning confirmation
- Reflected origin/IP redaction
- Response Analysis tab output
- Severity Summary output
- Pretty JSON response formatting
- Timestamped default report filename
- Latest API HTML/JSON artifact saving
- Active case display
- Open Case API Folder button
- Unified Report API artifact detection
- Unified Report Manual API Tester summary
- Empty Unified Report section hiding
- Unified Report preview formatting

Expected Manual API Tester artifact output:

```text
cases/<case_name>/api_analysis/manual_api_latest.html
cases/<case_name>/api_analysis/manual_api_latest.json
```

Expected Manual API Tester Summary fields in Unified Report:

```text
Tool: manual_api_tester
Saved at: <timestamp>
Redaction: Enabled or Disabled / Full Evidence
Method: GET
URL: <tested endpoint>
Verify SSL: True
Timeout: 60 seconds
HTTP status: 200
Content-Type: application/json
Elapsed: <seconds>
Response size: <size>
Analysis findings:
  [Info] Successful HTTP response received.
  [Info] HTTPS transport used.
  [Info] JSON response detected.
Severity Summary:
  High: <count>
  Medium: <count>
  Low: <count>
  Info: <count>
```

`v1.7` was validated with static and dynamic smoke tests.

Validated static/dynamic checks included:

- Notepad static smoke test
- Notepad dynamic smoke test
- Notepad dynamic timeout behavior
- Notepad dynamic cancellation during Autoruns before snapshot
- Notepad dynamic cancellation during sample observation
- Procmon disabled scenario
- Procmon missing scenario
- Autorunsc missing scenario
- Wireshark static smoke test
- Wireshark installer dynamic smoke test
- Static sample-specific report filename validation
- Dynamic sample-specific report filename validation
- Clean source package validation with old release folders removed from the archive

Expected clean Notepad dynamic indicators:

```text
Dynamic Score: Low / Clean Baseline
Spawned Processes: 0 non-noise attributed
Suspicious Paths: 0
Persistence Hits: 0
Autoruns Suspicious: 0
Scheduled Task Suspicious: 0
Service Diff Suspicious: 0
Dropped Files Suspicious: 0
```

Expected Wireshark installer dynamic behavior:

```text
Capture Quality: good
Verdict: Low Suspicion or Needs Review depending on observed activity
Npcap/Wireshark installer context visible
Autoruns suspicious new/modified entries: 0 for trusted clean install behavior
Service/task findings reviewed in installer context
```

---

## External Tooling Notice

The `v1.9.0` release package does **not** include third-party tools, external binaries, malware-analysis utilities, generated case folders, Procmon captures, or old release folders.

Users must download and configure external tools themselves.

This keeps the release package cleaner and avoids redistributing external software that should be obtained from original vendors or official project sources.

### Not Included in the Release Package

The following are not bundled in the `v1.9.0` release ZIP:

- Sysinternals Procmon
- Sysinternals Autorunsc
- Sysinternals ProcDump
- Process memory dumps (`.dmp`)
- capa executable
- capa rules
- capa signatures
- FLOSS executable
- YARA executable
- YARA rules
- VirusTotal API key
- Generated case folders
- Static analysis outputs
- Dynamic analysis outputs
- Manual API Tester outputs
- API Spec outputs
- Browser Extension outputs
- Procmon `.pml` captures
- Old release folders
- PyInstaller build folders
- Python virtual environment

### Recommended Tools to Download Separately

#### Dynamic Analysis Tools

For full dynamic analysis functionality.

> **Quick path:** run `scripts/bootstrap_tools.ps1` inside the analysis VM as
> Administrator. It downloads and installs Sysmon, Wireshark/Npcap, FakeNet-NG
> and ProcDump, then verifies each with the same preflight checks the Dynamic
> Analysis window uses. Follow it with `scripts/bootstrap_yara_rules.ps1` for the
> rules that memory scanning needs. The manual steps below are the equivalent.

- **Sysmon**
  - Provides process injection, image load, WMI persistence, DNS query and
    named pipe telemetry. None of this is visible to Procmon.
  - Install in the guest with a configuration, for example:

```text
sysmon64.exe -accepteula -i sysmonconfig.xml
```

  - Recommended path for the binary:

```text
tools/sysmon64.exe
```

- **Wireshark (dumpcap and tshark)**
  - `dumpcap` records the capture; `tshark` extracts DNS, TLS SNI, HTTP and
    connections. The Npcap driver bundled with Wireshark is required.
  - Found automatically in `C:\Program Files\Wireshark`, on `PATH`, or under
    `tools/`. Without `tshark` the pcap is still saved for manual analysis.
  - `pktmon` is used as a fallback when Wireshark is absent.

- **FakeNet-NG**
  - Serves a simulated internet so samples proceed through their real logic,
    and keeps the detonation from reaching live infrastructure.
  - Antivirus classifies it as a HackTool and will quarantine it; exclude the
    tools directory inside the VM.
  - Recommended path:

```text
tools/fakenet/fakenet.exe
```

- **ProcDump**
  - Writes the process memory images that memory YARA scans. The 64-bit build
    is required: `procdump.exe` cannot dump a 64-bit process, and a dump of the
    wrong bitness looks valid while scanning as though the sample did nothing.
  - Needs Administrator rights, since opening another process for a full dump
    requires debug privilege.
  - Recommended path:

```text
tools/procdump64.exe
```

- **YARA rules**
  - Without rules a dump is just a large file: the run writes it and reports
    "not scanned". `scripts/bootstrap_yara_rules.ps1` installs a ruleset and
    quarantines any rule that fails to compile.
  - Prefer string- and memory-oriented rules. Anything built on the `pe` module
    cannot match a raw process dump.
  - Recommended paths:

```text
tools/yara/rules/          downloaded ruleset, replaced on every bootstrap
tools/yara/local/          hand-maintained rules, preserved across updates
```

- **Procmon / Procmon64**
  - Used for runtime process, file, registry, and network event capture.
  - Recommended path:

```text
tools/Procmon64.exe
```

or:

```text
tools/Procmon.exe
```

- **Autorunsc / Autorunsc64**
  - Used for Autoruns before/after persistence snapshots.
  - Recommended path:

```text
tools/autorunsc64.exe
```

or:

```text
tools/autorunsc.exe
```

#### Static Analysis Tools

For stronger static analysis:

- **capa**
  - Used for capability and behavior rule matching.
  - Recommended path:

```text
tools/capa/capa.exe
```

- **capa rules**
  - Required for capa rule matching.
  - Recommended path:

```text
tools/capa/rules/
```

- **capa signatures**
  - Used by capa for richer binary analysis.
  - Recommended path:

```text
tools/capa/sigs/
```

- **FLOSS**
  - Used for decoded-string recovery.
  - Recommended path:

```text
tools/floss/floss.exe
```

- **YARA**
  - Used for YARA rule scanning when configured.
  - Recommended path:

```text
tools/yara/yara64.exe
```

or:

```text
tools/yara/yara.exe
```

- **YARA rules**
  - User-provided rules for static scanning.
  - Recommended path:

```text
tools/yara/rules/
```

#### Optional Services / Configuration

- **VirusTotal API key**
  - Required only if VirusTotal enrichment is enabled.
  - Users must provide their own API key.
  - Do not commit API keys to Git.

- **WeasyPrint**
  - Optional Python dependency for direct PDF report generation.
  - If unavailable, use the HTML report and browser print-to-PDF.

### Expected Local Tool Folder Example

A fully configured local analysis environment may look like:

```text
tools/
  Procmon64.exe
  autorunsc64.exe

  capa/
    capa.exe
    rules/
    sigs/

  floss/
    floss.exe

  yara/
    yara64.exe
    rules/

  procmon-configs/
    dynamic_default.pmc
```

RingForge can still run with some tools missing, but functionality will be reduced:

- Without Procmon, dynamic runtime telemetry is not collected.
- Without Autorunsc, Autoruns persistence diffing is skipped.
- Without capa, static capability analysis is reduced.
- Without FLOSS, decoded-string recovery is reduced.
- Without YARA rules, YARA scanning is skipped or reported as incomplete.
- Without a VirusTotal API key, VirusTotal enrichment is unavailable.

---

## Workflow Launcher

RingForge opens into a launcher that provides access to:

- Static Analysis
- Dynamic Analysis
- Manual API Tester
- Spec Analysis
- Browser Extension Analysis
- Unified Report

The launcher is designed to keep workflows separated while allowing related analysis modules to contribute to the same case.

---

## Output Structure

RingForge uses case-based output folders.

A typical case may look like:

```text
cases/
  <case_name>/
    case_metadata.json
    combined_score.json

    metadata/
      static_run_summary.json
      combined_score.json

    static_analysis/
      <sample>_static_report.html
      <sample>_static_report.md
      report.html
      report.md
      summary.json
      runlog.json
      analysis.log
      api_analysis.json
      iocs.json
      iocs.csv
      strings.txt
      capa.json
      pe_metadata.json
      lief_metadata.json
      signing.json
      virustotal.json
      extracted/
      subfiles/
      metadata/

    dynamic_analysis/
      reports/
        <sample>_dynamic_report.html
        dynamic_report.html

      dynamic_runs/
        <sample>_<timestamp>_<run_id>/
          metadata/
            dynamic_run_summary.json
            run_config.json
            sample_info.json

          procmon/
            raw.pml
            export.csv
            parsed_events.json
            interesting_events.json

          persistence/
            tasks_before.json
            tasks_after.json
            task_diffs.json
            services_before.json
            services_after.json
            service_diffs.json

          autoruns/
            autoruns_before.csv
            autoruns_after.csv
            autoruns_diff.json

          files/
            dropped_files.json
            dropped_files_summary.json

          reports/
            dynamic_findings.json

    api_analysis/
      manual_api_latest.html
      manual_api_latest.json

    spec_analysis/
      api_spec_analysis.json
      spec_inventory_latest.html
      spec_inventory_latest.json

      downloaded_specs/
        <downloaded_spec_file>

      metadata/
        api_spec_analysis.json

      originals/
        original_<spec_name>.<ext>

      runs/
        <timestamp>_<spec_name>/
          api_spec_analysis.json
          spec_inventory.html
          spec_inventory.json
          original_<spec_name>.<ext>

    extension_analysis/
      extension_analysis.json
      reports/

    unified_report/
      unified_report.html
```

Note: some compatibility report names are intentionally retained so older GUI buttons and unified report paths continue to work.

---

## Repository Layout

```text
ringforge-workbench/
  assets/
  docs/
  dynamic_analysis/
  gui/
  scripts/
  static_triage_engine/
  test_specs/
  tools/
  triage_inbox.py
  requirements.txt
  README.md
  LICENSE
```

Important folders:

| Folder | Purpose |
|---|---|
| `assets/` | Branding and UI assets |
| `docs/` | `WORKFLOW.md`, the detonation procedure and why each step is ordered as it is. `HANDOFF.md`, the current state of the work: what is validated, what is known-broken, and what is worth doing next |
| `dynamic_analysis/` | Dynamic collection, parsing, scoring, and reporting. Includes `sysmon_collector.py`, `network_capture.py`, `fakenet_runner.py`, `memory_dump.py`, and `memory_yara.py` |
| `gui/` | Tkinter GUI windows, launcher, controllers, and styles. `theme.py` holds the design tokens; `components.py` the shared widgets |
| `scripts/` | Entry points and helper scripts, including `bootstrap_tools.ps1` (guest setup), `bootstrap_yara_rules.ps1` (YARA rules), `vm_hygiene.ps1` (guest noise reduction), and `vm_net.ps1` (host containment) |
| `test_specs/` | Test inputs, including the `memory_canary/` memory-dump self-test |
| `static_triage_engine/` | Static analysis engine, scoring, and reporting |
| `tools/` | Local helper tool paths and configuration folders |
| `triage_inbox.py` | Helper entry point / inbox workflow |

The release archive is intended to contain the packaged application and documentation. Local folders such as `.venv/`, generated `cases/`, and temporary build artifacts should not be included in source archives.

---

## Requirements

### Hypervisor

**VirtualBox is not required.** The analysis engine is hypervisor-agnostic: it
runs inside whatever Windows machine you point it at, and nothing in
`static_triage_engine/`, `dynamic_analysis/` or `gui/` knows or cares what it is
running on. Sysmon, packet capture, FakeNet-NG, ProcDump and the memory YARA
scan are all ordinary Windows tooling.

Two host-side convenience scripts are VirtualBox-specific, because they drive
`VBoxManage`:

| Script | What you lose without VirtualBox |
|---|---|
| `vm_net.ps1` | Arming and disarming the guest's internet adapter from the host |
| `vm_snapshot.ps1` | Taking and restoring snapshots, and reverting between detonations |

On VMware, Hyper-V, Proxmox or anything else, do those two things through your
own hypervisor's tooling instead. Both are single operations there: disconnect
the network adapter, and revert to a snapshot.

Importantly, you do not lose the *verification*. Containment is checked inside
the guest by counting egress paths, which is an operating-system fact rather
than a hypervisor one, so `network_isolation` in the run summary still tells you
independently whether the machine was actually isolated. That check is what you
should trust regardless of how you disconnected the adapter.

What it guards against is a **second** adapter letting a sample bypass FakeNet's
redirect, not the existence of a route. A single egress path over a private
network reads as contained, and that matters, because:

> **The guest needs one default route for the simulated internet to work at
> all.** FakeNet diverts packets. With no default route Windows rejects a send
> to any off-link address before a packet exists, so there is nothing to
> intercept and the listeners sit configured and unreachable — a sample's C2
> lookup simply times out. Point a default route at the host-only gateway
> (`route -p add 0.0.0.0 mask 0.0.0.0 <host-only gateway>`). That segment is not
> forwarded or NATed, and the internet-facing adapter stays disconnected, so
> containment is preserved. Without it the report says **Simulated Internet
> Cannot Be Reached** rather than leaving you to infer it.

`bootstrap_tools.ps1` likewise recognises VMware, QEMU, Xen, Parallels and
Hyper-V guests, not just VirtualBox, when deciding whether it is safe to install
kernel drivers.

### Python

Python `3.11` or `3.12` is recommended.

### Python Packages

Install dependencies from `requirements.txt`.

Common packages include:

- `requests`
- `pefile`
- `lief`
- `pyyaml`
- `pillow`
- `psutil`
- `yara-python`
- `pyinstaller`
- `weasyprint` optional for direct PDF generation

---

## Windows Setup

From PowerShell:

```powershell
cd C:\RingForge_Analyzer\Static-Software-Malware-Analysis

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

Optional PDF support:

```powershell
pip install weasyprint
```

If PDF dependencies are unavailable, open the HTML report and use the browser's print-to-PDF option.

---

## Running the GUI

From the project root:

```powershell
cd C:\RingForge_Analyzer\Static-Software-Malware-Analysis
.\.venv\Scripts\Activate.ps1
python .\scripts\static_triage_gui.py
```

---

## Basic Static Analysis Workflow

1. Launch RingForge.
2. Open **Static Analysis**.
3. Select a Windows sample such as an EXE or DLL.
4. Enter or confirm the case name.
5. Run static analysis.
6. Review score, verdict, confidence, VirusTotal context, API import context, subfile context, and report artifacts.
7. Open the static report from the Artifacts section.

Expected static report locations:

```text
cases/<case_name>/static_analysis/<sample>_static_report.html
cases/<case_name>/static_analysis/report.html
```

`report.html` is kept as a compatibility copy.

---

## Basic Dynamic Analysis Workflow

Dynamic analysis should be run inside an isolated Windows VM.

1. Launch RingForge.
2. Open **Dynamic Analysis**.
3. Select the sample.
4. Confirm the case directory and dynamic output directory.
5. Confirm Procmon and Autorunsc paths.
6. Configure timeout, minimum observation, post-exit observation, and installer mode.
7. Run Dynamic Analysis.
8. Allow the sample to execute under observation.
9. For installers, complete the installer normally and allow first-run behavior to occur.
10. Review the dynamic findings summary and HTML report.

Expected dynamic report locations:

```text
cases/<case_name>/dynamic_analysis/reports/<sample>_dynamic_report.html
cases/<case_name>/dynamic_analysis/reports/dynamic_report.html
```

`dynamic_report.html` is kept as a compatibility copy.

---

## Basic Manual API Tester Workflow

1. Launch RingForge.
2. Open **Manual API Tester**.
3. Select a preset or enter a custom method and URL.
4. Add request headers as JSON.
5. Add a request body if needed.
6. Optionally select a file for multipart upload testing.
7. Click **Send Request**.
8. Review:
   - Analysis
   - Body
   - Headers
   - Raw
9. Use **Pretty JSON** if the body is valid JSON and needs formatting.
10. Choose whether to keep **Redact report** enabled.
11. Save the HTML report.

When saving, RingForge writes:

- an analyst-selected export report
- a latest case copy for Unified Report integration

Expected API artifact locations:

```text
cases/<case_name>/api_analysis/manual_api_latest.html
cases/<case_name>/api_analysis/manual_api_latest.json
```

---

## Basic API Spec Analysis Workflow

1. Launch RingForge.
2. Open **Spec Analysis**.
3. Select a local OpenAPI/Swagger file or paste a direct specification URL.
4. Click **Analyze Spec**.
5. Review:
   - Overview tiles
   - Authentication summary
   - Risk notes
   - Notable endpoints
   - Recommended manual tests
   - Endpoint inventory
6. Use **Open Latest Report** to open the latest HTML report.
7. Use **Open Case Files** to review generated JSON/HTML artifacts.
8. Open the Unified Report for the same case to confirm Spec Score and API-specific verdict integration.

Example test URL:

```text
https://petstore3.swagger.io/api/v3/openapi.json
```

Expected API Spec Analysis artifact locations:

```text
cases/<case_name>/spec_analysis/api_spec_analysis.json
cases/<case_name>/spec_analysis/spec_inventory_latest.html
cases/<case_name>/spec_analysis/spec_inventory_latest.json
cases/<case_name>/spec_analysis/runs/<timestamp>_<spec_name>/
```

---

## Dynamic Analysis Artifacts

A dynamic run may produce:

| Artifact | Description |
|---|---|
| `dynamic_run_summary.json` | Main structured dynamic summary |
| `run_config.json` | Resolved dynamic run configuration |
| `sample_info.json` | Sample hash and metadata information |
| `raw.pml` | Raw Procmon capture |
| `export.csv` | Exported Procmon CSV |
| `parsed_events.json` | Parsed Procmon events |
| `interesting_events.json` | Filtered interesting runtime events |
| `tasks_before.json` | Scheduled tasks before execution |
| `tasks_after.json` | Scheduled tasks after execution |
| `task_diffs.json` | Scheduled task diff |
| `services_before.json` | Services before execution |
| `services_after.json` | Services after execution |
| `service_diffs.json` | Service diff |
| `autoruns_before.csv` | Autoruns snapshot before execution |
| `autoruns_after.csv` | Autoruns snapshot after execution |
| `autoruns_diff.json` | Autoruns persistence diff |
| `dropped_files.json` | Dropped-file candidates |
| `dropped_files_summary.json` | Dropped-file summary |
| `memory/*.dmp` | Process memory dumps, named `<process>_<pid>_t<offset>[_exit].dmp` |
| `memory/memory_dumps.json` | Dump records: pid, image, offset, trigger, size, SHA-256 |
| `memory/memory_yara.json` | YARA results per dump, the on-disk baseline scan, and the memory-only rule list |
| `<sample>_dynamic_report.html` | Analyst-readable dynamic report |
| `dynamic_report.html` | Compatibility copy of the dynamic report |

---

## Manual API Tester Artifacts

The Manual API Tester may produce:

| Artifact | Description |
|---|---|
| `manual_api_latest.html` | Latest case-linked API HTML report |
| `manual_api_latest.json` | Latest case-linked structured API result |
| `api_test_report_<timestamp>.html` | User-selected exported API report |

The structured JSON artifact includes request metadata, response metadata, response analysis, redaction status, and report paths.

---

## API Spec Analysis Artifacts

The API Spec Analysis module may produce:

| Artifact | Description |
|---|---|
| `api_spec_analysis.json` | Latest canonical structured API spec result |
| `spec_inventory_latest.html` | Latest analyst-readable API spec HTML report |
| `spec_inventory_latest.json` | Latest structured API spec inventory |
| `metadata/api_spec_analysis.json` | Compatibility/latest metadata copy |
| `downloaded_specs/` | Downloaded OpenAPI/Swagger files when a URL is provided |
| `originals/` | Preserved latest source specifications |
| `runs/<timestamp>_<spec_name>/` | Historical spec run folder |
| `runs/<timestamp>_<spec_name>/spec_inventory.html` | Historical run HTML report |
| `runs/<timestamp>_<spec_name>/spec_inventory.json` | Historical run JSON report |

---

## Reporting

RingForge produces module-specific reports and supports a unified report workflow.

Current report types include:

- Static HTML report
- Static Markdown report
- Dynamic HTML report
- Manual API Tester HTML report
- API Spec report
- Browser Extension report
- Unified report

Reports are designed to be readable by analysts and suitable for review, documentation, and portfolio demonstration.

---

## Safety Notes

Dynamic analysis should only be performed inside an isolated, revertible analysis VM.

Do not run unknown or suspicious samples on a daily-use host.

Recommended safety practices:

- Use a dedicated Windows VM.
- Take a snapshot before testing.
- Disable shared clipboard and shared folders when testing unknown malware.
- Use a host-only or isolated network when appropriate.
- Revert the VM after risky testing.
- Treat all unknown binaries, installers, scripts, and extensions as potentially unsafe.

API testing can also expose sensitive information.

Recommended API testing practices:

- Avoid using production API keys unless required.
- Prefer test keys and controlled endpoints.
- Keep **Redact report** enabled for shareable reports.
- Use unredacted full-evidence reports only when intentionally preserving evidence.
- Treat exported reports as sensitive if they contain URLs, tokens, cookies, headers, IP addresses, or file paths.

RingForge is a triage and analyst workflow tool. It does not replace a full malware sandbox, EDR, SIEM, API security scanner, or reverse-engineering suite.

---

## Version History

### v1.9.0 — Tier-2 Process Memory + YARA

- Added process memory dumping with ProcDump during the observation window,
  driven by a watcher thread alongside the detonation
- Every run profile dumps early as well as late, so a loader that exits within
  seconds is still captured
- A root process exiting triggers an extra dump of surviving processes, in
  addition to the remaining scheduled offsets
- Liveness is tracked through handles captured while processes were running, so
  a recycled Windows PID cannot be dumped in place of the sample
- Added YARA scanning over the dumps and the on-disk sample in a single compiled
  pass
- Rules matching memory but not disk are weighted like injection and set a
  minimum severity of Medium; matches present in both score 1 point
- Match offsets reported as dump-file offsets, never virtual addresses
- Added `scripts/bootstrap_yara_rules.ps1`, with per-file compile checking and
  quarantine of rules that cannot compile
- Added `tools/yara/local/` for hand-maintained rules that survive a ruleset
  update
- Added a benign memory-dump self-test under `test_specs/memory_canary/`
- Pinned `yara-python`, which was absent from requirements entirely
- Case folders now follow the selected sample rather than persisting from the
  previous run
- Fixed rounded card, button and badge outlines rendering with pieces missing

### v1.8.0 — Tier-1 Dynamic Telemetry + UI Redesign

- Added Sysmon collection: injection, process tampering, LSASS access, WMI
  persistence, DNS queries, named pipes
- Added full packet capture with DNS, TLS SNI, HTTP and connection extraction
- Added FakeNet-NG simulated internet with per-process connection attribution
- Added network containment checking before every run, including IPv6 egress
- Windows baseline traffic separated from sample-attributable indicators in
  both findings and scoring
- Severity floor: injection, credential access and WMI persistence never
  report as Low
- Telemetry coverage reported explicitly, so a missing source is not mistaken
  for a clean result
- Scheduled task and service snapshots fall back to `schtasks.exe` / `sc.exe`
  when CIM namespaces are unavailable
- Added `scripts/bootstrap_tools.ps1` (guest) and `scripts/vm_net.ps1` (host)
- Rebuilt the interface on a shared design system: `gui/theme.py`,
  `gui/components.py`, and a single central `gui/styles.py`

### v1.7.2 — API Spec Analysis Polish + Unified Report Integration

- Added direct URL support for OpenAPI/Swagger specifications.
- Added downloaded spec storage under the active case folder.
- Standardized API Spec Analysis output under `spec_analysis/`.
- Added `spec_inventory_latest.html`, `spec_inventory_latest.json`, and `api_spec_analysis.json` as latest/canonical artifacts.
- Added clean historical run folders under `spec_analysis/runs/`.
- Added source spec preservation under `spec_analysis/originals/`.
- Improved Spec Analysis wording from **Top Risky Endpoints** to **Notable Endpoints**.
- Improved auth-gap wording so findings are tied to declared spec behavior.
- Improved recommended-test language to emphasize runtime validation.
- Added Spec Score and API-specific verdict support to the Unified Report.
- Added API Analysis and Browser Extension Analysis rows to the Unified Report overview.
- Added clearer `Not run` and `Not generated` labels for missing modules.

### v1.7.1 — Manual API Tester Polish + Unified Report Integration

- Added Manual API Tester Response Analysis tab.
- Added API response severity summary counts.
- Added Pretty JSON response formatting.
- Added timestamped default API report names.
- Added redacted report mode and unredacted evidence mode.
- Added redaction status to API reports.
- Added reflected origin/IP redaction for test APIs such as HTTPBin.
- Added active case display and Open Case API Folder button.
- Saved latest Manual API Tester HTML/JSON artifacts into the active case folder.
- Integrated Manual API Tester findings into the Unified Report.
- Hid empty Unified Report sections.
- Improved Unified Report preview formatting.
- Improved Manual API Tester Summary formatting in generated reports.
- Fixed API Tester dialog/messagebox parent behavior.
- Improved Manual API Tester response area sizing.
- Stabilized API Tester tab styling.
- Wired API import analysis into static scoring.

### v1.7 — Static + Dynamic Analysis Polish

- Polished static analysis stability, cancellation handling, deep triage warning behavior, subfile progress, subfile reporting, VirusTotal status handling, and friendly PKCS9/TSTInfo warning behavior.
- Added sample-specific static report names while keeping `report.html` and `report.md` compatibility copies.
- Added editable dynamic observation settings.
- Improved installer-aware dynamic observation and post-exit capture.
- Improved dynamic cancellation and partial-summary behavior.
- Added timeout explanation for GUI applications that remain open.
- Improved Procmon/Autorunsc disabled, missing, skipped, and cancelled states.
- Improved dynamic report readability and table formatting.
- Reduced dynamic false positives from normal Windows service state changes and installer helper behavior.
- Added sample-specific dynamic report names while keeping `dynamic_report.html` compatibility copy.
- Cleaned release packaging so old release folders are not included.

### v1.6.2 — Dynamic Analysis Stabilization + Autoruns Baseline

- Added Autorunsc before/after persistence diffing.
- Added Autoruns section to the dynamic report.
- Fixed static report path handling for the newer folder structure.
- Improved dynamic report verdict alignment.
- Improved analyzer noise filtering.
- Improved Windows 11 Notepad baseline filtering.
- Improved Dynamic Analysis GUI auto-sizing.
- Improved unified report compatibility.

### v1.6 — Startup, Launcher, and Browser Extension Analysis

- Added branded splash screen.
- Added launcher/home workflow selector.
- Added Browser Extension Analysis.
- Added support for unpacked, ZIP, and CRX extension analysis.
- Added extension manifest parsing, file inventory, risk notes, and HTML/JSON export.

### v1.5 — GUI Modularization

- Split major GUI windows into dedicated modules.
- Moved styling into reusable GUI style logic.
- Improved maintainability and future workflow expansion.

### v1.4 — Analysis Quality and False Positive Reduction

- Improved dynamic scoring.
- Improved signature handling.
- Added capa timeout and large-file handling.
- Improved YARA/report visibility.
- Hardened API Spec Analysis context.

---

## Interview / Portfolio Summary

RingForge Workbench demonstrates practical Python development applied to security analysis workflows.

Key engineering areas represented:

- Python GUI development
- Static malware/software triage
- Dynamic behavior collection
- Procmon parsing and event filtering
- Autoruns persistence diffing
- Manual API testing workflow design
- API response evidence reporting
- API specification parsing and report generation
- OpenAPI/Swagger URL ingestion
- API import analysis and scoring
- JSON artifact generation
- HTML report generation
- Scoring and verdict logic
- Analyst workflow design
- Case-based output organization
- False-positive reduction and baseline tuning
- Installer-aware runtime observation
- Report usability and workflow polish

---

## Roadmap

Planned future improvements:

- Browser Extension Analysis polish
- Additional API Spec Analysis depth and rule tuning
- Cleaner v1.8 case artifact organization
- Dynamic profile presets
- More dynamic baseline profiles
- Additional service and network noise tuning
- Optional network snapshot support
- Improved unified report integration with sample-specific report names
- Additional report templates
- Expanded API and browser extension analysis depth
- Improved packaged release workflow
- Request history and custom API tester presets
- Enhanced severity scoring across module reports

---

## License

This project is licensed under the MIT License.

See `LICENSE` for details.
