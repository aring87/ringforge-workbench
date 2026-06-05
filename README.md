# RingForge Workbench

[![Release](https://img.shields.io/badge/release-v1.7-blue)](https://github.com/aring87/ringforge-workbench/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://github.com/aring87/ringforge-workbench)
[![Python](https://img.shields.io/badge/python-3.12-yellow)](https://www.python.org/)
[![Analysis](https://img.shields.io/badge/analysis-static%20%7C%20dynamic%20%7C%20api%20%7C%20spec%20%7C%20browser%20extension-orange)](https://github.com/aring87/ringforge-workbench)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)](https://github.com/aring87/ringforge-workbench)

**Static insight. Dynamic visibility. Structured review.**

RingForge Workbench is a Python/Tkinter software triage platform for structured static analysis, dynamic behavior review, API testing, API specification review, and browser extension analysis from one analyst-facing interface.

The project is designed for malware analysts, SOC analysts, detection engineers, and security practitioners who want a practical Windows-focused workbench for reviewing software behavior, organizing case artifacts, and producing consistent reports.

---

## Current Release

| Field | Value |
|---|---|
| Version | `v1.7` |
| Release Name | Dynamic Analysis Polish |
| Platform Focus | Windows analysis environment |
| Language | Python |
| License | MIT |

---

## Project Summary

RingForge Workbench organizes software review into case-based workflows. Each case can contain static results, dynamic runtime results, supporting artifacts, and analyst-readable reports.

The tool is not intended to replace a full malware sandbox or reverse-engineering suite. It is a practical triage workbench that helps an analyst collect repeatable evidence, reduce noise, and produce readable static and dynamic reports.

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
- Subfile extraction and subfile triage
- HTML and Markdown reporting
- Optional PDF reporting when supported by the environment

### Dynamic Analysis

Dynamic Analysis supports controlled runtime behavior review inside a Windows analysis VM.

Current dynamic capabilities include:

- Procmon-backed event collection
- Parsed runtime event review
- Interesting event filtering
- Process creation tracking
- Dropped-file candidate review
- Scheduled task before/after diffing
- Service before/after diffing
- Autoruns before/after persistence diffing
- Capture quality scoring
- Dynamic scoring and verdicting
- Installer-aware observation mode
- Analyst cancellation support
- HTML dynamic report generation
- Clean baseline checks
- Installer context notes
- Noise filtering for RingForge tools, Procmon, Autorunsc, and common Windows helper behavior

### API Analysis

The API Analysis workflow supports manual analyst testing of API endpoints and application or service behavior.

It focuses on:

- Manual request testing
- HTTP status review
- Response time review
- Content type review
- Response size review
- Response body inspection
- Structured analyst workflow through the API window

### API Specification Analysis

Spec Analysis supports OpenAPI and Swagger-style definition review.

It can help identify:

- Endpoint inventory
- HTTP methods
- Authentication-related patterns
- Potentially sensitive routes
- Risk-oriented API surface review
- Follow-up test ideas
- HTML inventory reports

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

---

## What’s New in v1.7

`v1.7` focuses on dynamic analysis polish, report clarity, installer behavior, cancellation handling, and cleaner analyst-facing report names.

### Added

- Added editable dynamic observation settings:
  - Sample observation timeout
  - Minimum observation time
  - Post-exit observation time
  - Installer observation mode
- Added installer-aware post-exit observation so Procmon does not stop too early when an installer launcher exits before background installation activity finishes.
- Added observation-setting warning when post-exit observation is longer than or equal to the sample timeout.
- Added capture quality notes for GUI applications that remain open and hit the configured timeout.
- Added sample-specific report filenames:
  - `<sample>_static_report.html`
  - `<sample>_static_report.md`
  - `<sample>_dynamic_report.html`
- Kept compatibility report copies:
  - `report.html`
  - `report.md`
  - `dynamic_report.html`

### Improved

- Improved Dynamic Analysis cancellation behavior.
- Improved cancelled dynamic run summary/report state.
- Improved dynamic GUI quick status details.
- Improved dynamic GUI sizing and report-action layout.
- Improved dynamic case/output folder synchronization to reduce cross-case result mixups.
- Improved dynamic report readability for:
  - Autoruns entries
  - Spawned processes
  - Suspicious path hits
  - Persistence hits
- Improved Procmon disabled/missing handling.
- Improved Autorunsc disabled/missing/skipped handling.
- Improved service-diff false positive handling for normal Windows runtime state changes.
- Improved Wireshark/Npcap installer context and scoring behavior.
- Improved Notepad clean-baseline behavior for Windows GUI observation.

### Fixed

- Fixed dynamic cancellation where the GUI displayed cancelled but the orchestrator could continue running.
- Fixed dynamic report wording for cancelled runs.
- Fixed sample observation behavior for launchers/installers that exit early.
- Fixed dynamic report tables where long column names could crush table layout.
- Fixed output/report status paths being too long and cutting off UI controls.
- Fixed dynamic output/case folder mismatch behavior.
- Fixed static and dynamic reports to use sample-specific names while maintaining compatibility report names.
- Fixed friendly timeout handling for Notepad-style GUI apps that remain open.

---

## Current Validation

`v1.7` was validated with both clean baseline and installer-style dynamic tests.

### Notepad Static Baseline

Expected result:

```text
Static verdict: benign or low risk
Signature: Microsoft verified
VirusTotal: clean or no malicious/suspicious signal
Report opens successfully
```

### Notepad Dynamic Baseline

Expected result:

```text
Dynamic verdict: Benign / Clean Baseline or Low Suspicion
Capture quality: good or timed_out with explanation
Scheduled task suspicious: 0
Service diff suspicious: 0
Autoruns suspicious: 0
Suspicious paths: 0
Persistence hits: 0
Dropped files suspicious: 0
```

For GUI applications that remain open, an exit code of `-1` can be normal if the configured observation timeout is reached. The dynamic report should show a capture note explaining that the sample did not exit before timeout.

### Wireshark Installer Dynamic Test

Expected result:

```text
Capture quality: good
Installer mode: enabled
Procmon: enabled
Autoruns: enabled
Wireshark/Npcap context appears in report
No suspicious Autoruns false positive
No suspicious service/task false positive
Report tables remain readable
Verdict: Low Suspicion or Needs Review depending on observed installer behavior
```

---

## Workflow Launcher

RingForge opens into a launcher that provides access to:

- Static Analysis
- Dynamic Analysis
- API Analysis
- Spec Analysis
- Browser Extension Analysis
- Unified Report

The launcher keeps workflows separated while allowing related analysis modules to contribute to the same case.

---

## Output Structure

RingForge uses case-based output folders.

A typical case may look like:

```text
cases/
  <case_name>/
    case_metadata.json
    combined_score.json

    static_analysis/
      <sample>_static_report.html
      <sample>_static_report.md
      report.html
      report.md
      summary.json
      runlog.json
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
```

### Report Naming

RingForge now writes sample-specific report names for easier review:

```text
<sample>_static_report.html
<sample>_static_report.md
<sample>_dynamic_report.html
```

It also keeps legacy compatibility copies:

```text
report.html
report.md
dynamic_report.html
```

Those compatibility copies are retained so existing buttons, workflows, scripts, and unified-report lookups continue to work.

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
| `dynamic_analysis/` | Dynamic collection, parsing, scoring, and reporting |
| `gui/` | Tkinter GUI windows, launcher, controllers, and styles |
| `scripts/` | Entry points and helper scripts |
| `static_triage_engine/` | Static analysis engine, scoring, and reporting |
| `tools/` | Local helper resources such as capa signatures, Procmon config, and optional external tools |

Release, build, and packaging outputs should not be committed into source control. Keep local build artifacts in ignored folders such as `dist/`, `build/`, or `release/`.

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
- `pyinstaller`
- `weasyprint` optional for direct PDF generation

### Optional External Tools

For best results, place external tools under the `tools/` folder.

Recommended dynamic tools:

```text
tools/
  Procmon64.exe
  Procmon.exe
  autorunsc64.exe
  autorunsc.exe
```

Recommended static resources:

```text
tools/
  capa/
    sigs/
  yara/
    rules/
```

Procmon and Autorunsc are Sysinternals tools and should be downloaded separately from Microsoft. Do not include third-party tools in a release package unless their license allows redistribution.

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

If needed:

```powershell
pip install lief
```

Optional PDF support:

```powershell
pip install weasyprint
```

If PDF dependencies are unavailable, open the HTML report and use the browser’s print-to-PDF option.

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
3. Select a Windows sample such as an EXE, DLL, or installer.
4. Enter or confirm the case name.
5. Run static analysis.
6. Review score, verdict, confidence, VirusTotal context, capa output, signature status, and report artifacts.
7. Open the static report from the Artifacts section.

Expected report locations:

```text
cases/<case_name>/static_analysis/<sample>_static_report.html
cases/<case_name>/static_analysis/report.html
```

---

## Basic Dynamic Analysis Workflow

Dynamic analysis should be run inside an isolated Windows VM.

1. Launch RingForge.
2. Open **Dynamic Analysis**.
3. Select the sample.
4. Confirm the case output folder.
5. Confirm Procmon and Autorunsc paths.
6. Set observation options.
7. Run Dynamic Analysis.
8. Allow the sample to execute under observation.
9. For installers, complete the installer normally and allow post-exit observation to continue.
10. Review the dynamic findings summary and HTML report.

Recommended quick baseline settings:

```text
Timeout: 30-60 seconds
Minimum observation: 10 seconds
Post-exit observation: 10 seconds
Installer mode: enabled
Procmon: enabled
Autoruns: enabled
```

Recommended installer settings:

```text
Timeout: 300-600 seconds
Minimum observation: 30 seconds
Post-exit observation: 60-120 seconds
Installer mode: enabled
Procmon: enabled
Autoruns: enabled
```

Expected dynamic report locations:

```text
cases/<case_name>/dynamic_analysis/reports/<sample>_dynamic_report.html
cases/<case_name>/dynamic_analysis/reports/dynamic_report.html
```

---

## Dynamic Analysis Artifacts

A dynamic run may produce:

| Artifact | Description |
|---|---|
| `dynamic_run_summary.json` | Main structured dynamic summary |
| `run_config.json` | Runtime configuration used for the dynamic run |
| `sample_info.json` | Sample metadata and hashes |
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
| `dropped_files.json` | Dropped-file candidate details |
| `dropped_files_summary.json` | Dropped-file summary |
| `<sample>_dynamic_report.html` | Analyst-readable dynamic report |
| `dynamic_report.html` | Compatibility copy of the latest dynamic report |

---

## Reporting

RingForge produces module-specific reports and supports a unified report workflow.

Current report types include:

- Static HTML report
- Static Markdown report
- Dynamic HTML report
- API test report
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

RingForge is a triage and analyst workflow tool. It does not replace a full malware sandbox, EDR, SIEM, or reverse-engineering suite.

---

## Packaging a Release

A clean source package can be created from a Git tag:

```powershell
git tag -a v1.7 -m "Release v1.7 dynamic polish"
git push origin v1.7

New-Item -ItemType Directory -Force .\dist | Out-Null
git archive --format zip --output .\dist\RingForge-Workbench-v1.7-source.zip v1.7
```

The source ZIP should not include:

```text
cases/
dist/
build/
release/
.venv/
old release folders
large Procmon captures
```

---

## Version History

### v1.7 — Dynamic Analysis Polish

- Added installer-aware dynamic observation settings.
- Added editable timeout, minimum observation, post-exit observation, and installer mode.
- Improved dynamic cancellation handling and cancelled report state.
- Added capture-quality timeout explanation for GUI apps that remain open.
- Improved Procmon and Autorunsc disabled, missing, skipped, and cancelled states.
- Improved dynamic report readability for Autoruns, spawned processes, suspicious path hits, and persistence hits.
- Reduced service-diff false positives from normal Windows runtime state changes.
- Added case/output folder synchronization to prevent cross-case dynamic result mixups.
- Added sample-specific static and dynamic report filenames while keeping compatibility report copies.
- Validated Notepad static/dynamic baseline and Wireshark installer dynamic workflow.

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
- JSON artifact generation
- HTML report generation
- Scoring and verdict logic
- Analyst workflow design
- Case-based output organization
- False-positive reduction and baseline tuning
- Release packaging and documentation

---

## Roadmap

Planned future improvements:

- Cleaner long-term case artifact organization
- Dynamic run comparison
- Network snapshot support
- Service-diff tuning profiles
- Tool health dashboard
- Improved dynamic baseline profiles
- More screenshots and usage examples
- Additional report templates
- Expanded API and browser extension analysis depth

---

## License

This project is licensed under the MIT License.

See `LICENSE` for details.
