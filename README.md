# RingForge Workbench

[![Release](https://img.shields.io/badge/release-v1.9.0-blue)](https://github.com/aring87/ringforge-workbench/releases)
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
| Version | `v1.9.0` |
| Release Name | Tier-2 Process Memory + YARA |
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
- scoring and verdict logic
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
- Process memory dumps of the sample's process tree during the run
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
- Noise filtering for RingForge tools, Procmon, Autorunsc, Windows helper activity, and common clean-baseline behavior
- Windows baseline network traffic separated from sample-attributable indicators
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
- Combined Score

The Unified Report now summarizes Manual API Tester findings, API Spec Analysis findings, Browser Extension Analysis status, and available static/dynamic results. It also uses clearer labels such as `Not run` and `Not generated` when a module has no artifacts in the selected case.

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

- A memory-only match is weighted like process injection and sets the same
  minimum severity of Medium. Matches present in both memory and on disk score
  1 point, because the static run already reported them.
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
| `scripts/bootstrap_tools.ps1` | Also installs ProcDump; the preflight check now covers five sources |
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

- A capture records the whole host, so Windows certificate-revocation,
  telemetry and mDNS traffic is classified as baseline and excluded from
  findings and scoring. Both lists are kept, since C2 does hide behind CDNs.
- Injection, credential access and WMI persistence set a minimum severity of
  Medium regardless of score, so a sample that does one decisive thing is never
  reported as Low.
- Telemetry coverage is stated explicitly. If Sysmon was not running, the
  report says so rather than reading as though no injection occurred.

### Resilience

- Scheduled task and service snapshots fall back to `schtasks.exe` and
  `sc.exe` when the CIM namespaces are missing, which is common on debloated
  Windows images used as VM bases. A failed snapshot no longer aborts the run.
- Antivirus quarantine of FakeNet-NG is recognised and explained as the
  expected false positive it is.

### Supporting Scripts

| Script | Runs on | Purpose |
|---|---|---|
| `scripts/bootstrap_tools.ps1` | Analysis VM | Installs Sysmon, Wireshark/Npcap and FakeNet-NG, then verifies with the workbench's own preflight checks |
| `scripts/vm_net.ps1` | Host | Arms and disarms the VM's internet adapter via VBoxManage, without a shutdown |

Both refuse to run in the wrong place: `bootstrap_tools.ps1` will not install
drivers outside a VM without `-Force`, and `vm_net.ps1` explains that
containment is only enforceable from the host.

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
  dynamic_analysis/
  gui/
  scripts/
  static_triage_engine/
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
| `dynamic_analysis/` | Dynamic collection, parsing, scoring, and reporting. Includes `sysmon_collector.py`, `network_capture.py`, `fakenet_runner.py`, `memory_dump.py`, and `memory_yara.py` |
| `gui/` | Tkinter GUI windows, launcher, controllers, and styles. `theme.py` holds the design tokens; `components.py` the shared widgets |
| `scripts/` | Entry points and helper scripts, including `bootstrap_tools.ps1` (guest setup), `bootstrap_yara_rules.ps1` (YARA rules), and `vm_net.ps1` (host containment) |
| `test_specs/` | Test inputs, including the `memory_canary/` memory-dump self-test |
| `static_triage_engine/` | Static analysis engine, scoring, and reporting |
| `tools/` | Local helper tool paths and configuration folders |
| `triage_inbox.py` | Helper entry point / inbox workflow |

The release archive is intended to contain the packaged application and documentation. Local folders such as `.venv/`, generated `cases/`, and temporary build artifacts should not be included in source archives.

---

## Requirements

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
