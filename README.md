# RingForge Workbench

[![Release](https://img.shields.io/badge/release-v1.7-blue)](https://github.com/aring87/ringforge-workbench/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://github.com/aring87/ringforge-workbench)
[![Python](https://img.shields.io/badge/python-3.12-yellow)](https://www.python.org/)
[![Analysis](https://img.shields.io/badge/analysis-static%20%7C%20dynamic%20%7C%20api%20%7C%20spec%20%7C%20browser%20extension-orange)](https://github.com/aring87/ringforge-workbench)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)](https://github.com/aring87/ringforge-workbench)

**Static insight. Dynamic visibility. Structured review.**

RingForge Workbench is a Python/Tkinter software triage workbench for structured static analysis, dynamic behavior review, API testing, API specification review, and browser extension analysis from one analyst-facing interface.

It is designed for malware analysts, SOC analysts, detection engineers, and security practitioners who want a practical Windows-focused workflow for reviewing software behavior, organizing case artifacts, and producing consistent analyst-readable reports.

---

## Current Release

| Field | Value |
|---|---|
| Version | `v1.7` |
| Release Name | Static + Dynamic Analysis Polish |
| Platform Focus | Windows analysis environment |
| Language | Python |
| License | MIT |

---

## Project Summary

RingForge Workbench provides a modular case-based workflow for analyzing software samples and related artifacts. It supports static triage, dynamic runtime collection, API review, OpenAPI/Swagger specification review, and browser extension inspection.

The workbench emphasizes practical analyst outcomes:

- repeatable case folders
- structured JSON artifacts
- readable HTML/Markdown reports
- scoring and verdict logic
- baseline/noise reduction
- workflow-specific review screens
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
- Markdown and HTML reporting
- PDF reporting when optional PDF dependencies are available
- Extracted subfile triage
- Subfile scoring and report visibility
- Deep triage warnings and progress visibility

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
- Installer-aware observation settings
- Post-exit observation for installer handoff behavior
- Cancellation handling with partial summaries
- Dynamic scoring and verdicting
- HTML dynamic report generation
- Capture quality reporting
- Clean baseline checks
- Analyst notes
- Noise filtering for RingForge tools, Procmon, Autorunsc, Windows helper activity, and common clean-baseline behavior

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

## What’s New in v1.7

`v1.7` focuses on polishing both the static and dynamic analysis workflows. This release improves analyst usability, report clarity, cancellation behavior, installer observation, scoring context, case/output handling, and report naming.

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

`v1.7` was validated with:

- Notepad static smoke test.
- Notepad dynamic smoke test.
- Notepad dynamic timeout behavior.
- Notepad dynamic cancellation during Autoruns before snapshot.
- Notepad dynamic cancellation during sample observation.
- Procmon disabled scenario.
- Procmon missing scenario.
- Autorunsc missing scenario.
- Wireshark static smoke test.
- Wireshark installer dynamic smoke test.
- Static sample-specific report filename validation.
- Dynamic sample-specific report filename validation.
- Clean source package validation with old release folders removed from the archive.

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

The `v1.7` source package does **not** include third-party tools, external binaries, malware-analysis utilities, generated case folders, Procmon captures, or old release folders.

Users must download and configure external tools themselves.

This keeps the release package cleaner and avoids redistributing external software that should be obtained from original vendors or official project sources.

### Not Included in the Release Package

The following are not bundled in the `v1.7` source ZIP:

- Sysinternals Procmon
- Sysinternals Autorunsc
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
- Procmon `.pml` captures
- Old release folders
- PyInstaller build folders
- Python virtual environment

### Recommended Tools to Download Separately

#### Dynamic Analysis Tools

For full dynamic analysis functionality:

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
| `dynamic_analysis/` | Dynamic collection, parsing, scoring, and reporting |
| `gui/` | Tkinter GUI windows, launcher, controllers, and styles |
| `scripts/` | Entry points and helper scripts |
| `static_triage_engine/` | Static analysis engine, scoring, and reporting |
| `tools/` | Local helper tool paths and configuration folders |
| `triage_inbox.py` | Helper entry point / inbox workflow |

The release archive is intended to contain the source tree only. Local folders such as `dist/`, `build/`, `release/`, `.venv/`, and generated `cases/` should not be included in the source package.

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
6. Review score, verdict, confidence, VirusTotal context, subfile context, and report artifacts.
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
| `<sample>_dynamic_report.html` | Analyst-readable dynamic report |
| `dynamic_report.html` | Compatibility copy of the dynamic report |

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

- Cleaner v1.8 case artifact organization.
- Dynamic profile presets.
- More dynamic baseline profiles.
- Additional service and network noise tuning.
- Optional network snapshot support.
- Improved unified report integration with sample-specific report names.
- Additional report templates.
- Expanded API and browser extension analysis depth.
- Improved packaged release workflow.

---

## License

This project is licensed under the MIT License.

See `LICENSE` for details.
