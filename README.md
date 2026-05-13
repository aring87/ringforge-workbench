# RingForge Workbench

[![Release](https://img.shields.io/badge/release-v1.6.2-blue)](https://github.com/aring87/ringforge-workbench/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://github.com/aring87/ringforge-workbench)
[![Python](https://img.shields.io/badge/python-3.12-yellow)](https://www.python.org/)
[![Analysis](https://img.shields.io/badge/analysis-static%20%7C%20dynamic%20%7C%20api%20%7C%20spec%20%7C%20browser%20extension-orange)](https://github.com/aring87/ringforge-workbench)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)](https://github.com/aring87/ringforge-workbench)

**Static insight. Dynamic visibility. Structured review.**

RingForge Workbench is a Python-based software triage platform built for structured static analysis, dynamic behavior review, API testing, API specification review, and browser extension analysis from a single analyst-facing interface.

The project is designed for malware analysts, SOC analysts, detection engineers, and security practitioners who want a practical workbench for reviewing Windows software behavior, organizing case artifacts, and producing consistent reports.

---

## Current Release

| Field | Value |
|---|---|
| Version | `v1.6.2` |
| Release Name | Dynamic Analysis Stabilization + Autoruns Baseline |
| Platform Focus | Windows analysis environment |
| Language | Python |
| License | MIT |

---

## Project Summary

RingForge Workbench provides a modular workflow for analyzing software samples and related artifacts. It supports static triage, dynamic runtime collection, API review, OpenAPI/Swagger specification review, and browser extension inspection.

The tool is built around case-based output, structured scoring, and analyst-readable reporting. Each module is designed to produce its own results while also supporting unified reporting when multiple analysis types are run against the same case.

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
- Markdown and HTML reporting
- PDF reporting when supported by the environment

### Dynamic Analysis

Dynamic Analysis supports controlled runtime behavior review inside a Windows analysis VM.

Current dynamic capabilities include:

- Procmon-backed event collection
- Parsed runtime event review
- Interesting event filtering
- Process creation tracking
- Dropped-file summary
- Scheduled task before/after diffing
- Service before/after diffing
- Autoruns before/after persistence diffing
- Dynamic scoring and verdicting
- HTML dynamic report generation
- Clean baseline checks
- Analyst notes
- Noise filtering for RingForge tools, Procmon, Autorunsc, and common Windows 11 helper behavior

### API Analysis

The API Analysis workflow supports manual analyst testing of API endpoints and application/service behavior.

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

## What’s New in v1.6.2

`v1.6.2` stabilizes the dynamic analysis workflow and adds Autorunsc-based persistence baseline comparison.

### Added

- Added Sysinternals Autorunsc integration for dynamic persistence review.
- Captures Autoruns snapshots before and after sample execution.
- Generates Autoruns artifacts:
  - `autoruns_before.csv`
  - `autoruns_after.csv`
  - `autoruns_diff.json`
- Adds Autoruns persistence results into the dynamic run summary.
- Adds a dedicated **Autoruns Persistence Diff** section to the dynamic HTML report.
- Adds clean baseline checks and analyst notes to the dynamic report.

### Improved

- Improved dynamic case output structure.
- Improved dynamic HTML reporting layout.
- Fixed dynamic report banner verdict alignment with score and severity.
- Improved Dynamic Analysis GUI sizing for different screens and VM displays.
- Improved report path handling for the newer static and dynamic folder layout.
- Improved unified report compatibility with module-specific outputs.
- Improved Notepad baseline behavior for Windows 11 packaged-app execution.

### Fixed

- Fixed the static report open button to support the new path: `cases/<case>/static_analysis/report.html`.
- Fixed stale report path assumptions from the older case layout.
- Fixed Autorunsc CSV parsing when banner/header lines are present.
- Reduced analyzer noise from Procmon, Autorunsc, RingForge output folders, generated report artifacts, and dynamic run metadata.
- Reduced false spawned-process findings from normal Windows 11 Notepad behavior.
- Added filtering for common Windows helper processes:
  - `DllHost.exe`
  - `DataExchangeHost.exe`
  - `ApplicationFrameHost.exe`
  - `RuntimeBroker.exe`
  - `BackgroundTaskHost.exe`
  - packaged `WindowsApps\Notepad.exe /SESSION` behavior

---

## Current Dynamic Analysis Validation

The current `v1.6.2` baseline was validated with a clean `notepad.exe` test.

Expected clean-baseline behavior:

- Static report opens successfully.
- Dynamic report opens successfully.
- Autoruns before/after totals are non-zero.
- Autoruns suspicious new/modified entries are `0`.
- Process creates are filtered to `0` for benign Notepad baseline behavior.
- Spawned processes are empty when only Windows baseline helper activity is observed.
- Suspicious paths are `0`.
- Persistence hits are `0`.
- Dropped-file suspicious count is `0`.

Example clean dynamic indicators:

```text
Process Creates: 0
Spawned Processes: 0
Suspicious Paths: 0
Persistence Hits: 0
Autoruns Suspicious: 0
Scheduled Task Suspicious: 0
Service Diff Suspicious: 0
Dropped Files Suspicious: 0
```

---

## Known Limitations

- Dynamic scoring is still being tuned for benign Windows background noise such as MDE/Sense and `svchost.exe` network activity.
- Dynamic analysis is intended as a practical triage layer, not a full sandbox replacement.
- Some benign software may still generate elevated scores depending on installer behavior, services, drivers, persistence mechanisms, or network activity.
- Browser Extension Analysis is currently static review only and does not dynamically execute browser extensions.
- API Spec Analysis identifies review targets and risk patterns, but findings require analyst validation.
- PDF report generation depends on optional local dependencies. HTML reporting is the primary supported report format.

Planned for `v1.7`:

- Network noise tuning
- Service-diff scoring refinement
- Additional dynamic tool health checks
- Optional network snapshot support
- Improved dynamic score calibration
- Updated screenshots and packaged release workflow

---

## Workflow Launcher

RingForge opens into a launcher that provides access to:

- Static Analysis
- Dynamic Analysis
- API Analysis
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
    static_analysis/
      summary.json
      report.html
      report.md
      report.pdf
      iocs.json
      iocs.csv
      strings.txt
      capa.json
      capa.txt
      pe_metadata.json
      lief_metadata.json
      signing.json
      virustotal.json

    dynamic_analysis/
      dynamic_runs/
        <run_id>/
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
        dynamic_report.html

    unified_report/
      unified_report.html
```

---

## Repository Layout

```text
ringforge-workbench/
  assets/
  dynamic_analysis/
  gui/
  release/
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
| `tools/` | Local helper tools such as capa rules, Procmon, Autorunsc, and signatures |
| `release/` | Local packaged release output |

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
  capa-rules/
  capa/
    sigs/
```

Procmon and Autorunsc are Sysinternals tools and should be downloaded separately from Microsoft.

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
3. Select a Windows sample such as an EXE or DLL.
4. Enter or confirm the case name.
5. Run static analysis.
6. Review score, verdict, confidence, VirusTotal context, and report artifacts.
7. Open the static report from the Artifacts section.

Expected report location:

```text
cases/<case_name>/static_analysis/report.html
```

---

## Basic Dynamic Analysis Workflow

Dynamic analysis should be run inside an isolated Windows VM.

1. Launch RingForge.
2. Open **Dynamic Analysis**.
3. Select the sample.
4. Confirm the case directory.
5. Confirm Procmon and Autorunsc paths.
6. Run Dynamic Analysis.
7. Allow the sample to execute under observation.
8. For clean baseline tests like Notepad, close the application after a few seconds.
9. Review the dynamic findings summary and HTML report.

Expected dynamic report location:

```text
cases/<case_name>/dynamic_analysis/reports/dynamic_report.html
```

---

## Dynamic Analysis Artifacts

A dynamic run may produce:

| Artifact | Description |
|---|---|
| `dynamic_run_summary.json` | Main structured dynamic summary |
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
| `dropped_files_summary.json` | Dropped-file summary |
| `dynamic_report.html` | Analyst-readable dynamic report |

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

## Version History

### v1.6.2 — Dynamic Analysis Stabilization + Autoruns Baseline

- Added Autorunsc before/after persistence diffing.
- Added Autoruns section to the dynamic report.
- Fixed static report path handling for the new folder structure.
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

---

## Roadmap

Planned future improvements:

- v1.7 professional dynamic scoring calibration
- Network snapshot support
- Service-diff tuning
- Tool health checks
- Improved dynamic baseline profiles
- More screenshots and usage examples
- Improved packaged release workflow
- Additional report templates
- Expanded API and browser extension analysis depth

---

## License

This project is licensed under the MIT License.

See `LICENSE` for details.
