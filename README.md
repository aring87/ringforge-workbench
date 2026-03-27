# RingForge Workbench is a Static and Dynamic Software Analysis Platform

[![Release](https://img.shields.io/badge/release-v1.4-blue)](https://github.com/aring87/ringforge-workbench/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://github.com/aring87/ringforge-workbench)
[![Python](https://img.shields.io/badge/python-3.12-yellow)](https://www.python.org/)
[![Analysis](https://img.shields.io/badge/analysis-static%20%7C%20dynamic%20%7C%20spec-orange)](https://github.com/aring87/ringforge-workbench)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)](https://github.com/aring87/ringforge-workbench)

Static insight. Dynamic visibility.

RingForge Workbench is a unified software triage platform designed for static, dynamic, behavioral, and API specification analysis, scoring, and reporting.

The project brings together multiple analysis methods into a single workflow to support efficient triage, structured outputs, cleaner analyst review, and continued expansion into a broader software assessment workbench.

## Current Release

**Version:** v1.5

## Overview

RingForge Workbench is designed to help analysts quickly triage Windows software samples such as EXE, DLL, installer, launcher, and related package files. It combines metadata extraction, strings analysis, capa behavior analysis, IOC extraction, signing validation, VirusTotal reputation, executable API import analysis, controlled dynamic runtime behavior collection, and API specification analysis into a single workflow.

The platform creates case-based output for each workflow and produces structured artifacts such as JSON analysis files, IOC exports, Markdown and HTML reports, PDF reports when supported, Procmon-derived runtime artifacts, persistence diffs, dynamic findings summaries, and API spec inventory reports.

## Whats New in v1.5

RingForge Workbench v1.5 focuses on internal cleanup, GUI modularization, and maintainability improvements following the feature growth completed in v1.4. This release does not change the core mission of the platform, but it significantly improves the structure of the codebase so future features, fixes, and testing workflows can be added more safely and cleanly.

Version 1.5 begins the transition away from a large monolithic GUI file by splitting major interface components into dedicated modules. The API Analysis window, Dynamic Analysis window, Spec Analysis window, and application styling logic were separated into their own files under a new gui package. This makes the project easier to maintain, easier to troubleshoot, and safer to extend without introducing unrelated regressions.

In addition to the structural cleanup, v1.5 includes dependency and launch-path fixes required to support modular imports when the application is started from the existing scripts/static_triage_gui.py entry point. During refactoring, runtime issues affecting configuration save behavior and the Dynamic Analysis launch flow were identified and corrected, restoring full window functionality while preserving the existing user experience.

v1.5 Highlights
Began modular GUI refactor for improved maintainability
Moved API Analysis window into gui/api_window.py
Moved Dynamic Analysis window into gui/dynamic_window.py
Moved Spec Analysis window into gui/spec_window.py
Moved theme and ttk styling logic into gui/styles.py
Added gui package structure for cleaner separation of responsibilities
Improved compatibility for modular imports when launching from scripts/static_triage_gui.py
Removed several window dependencies on old global GUI constants and helpers
Fixed dynamic configuration save behavior after window modularization
Restored proper Run Dynamic Analysis button behavior after refactor
Preserved existing app behavior while reducing GUI file complexity
Established a cleaner foundation for future movement of shared helpers and main app logic
v1.5 Changelog
Added new gui package structure
Refactored APIAnalysisWindow into its own module
Refactored DynamicAnalysisWindow into its own module
Refactored SpecAnalysisWindow into its own module
Refactored theme application logic into gui/styles.py
Added project-root import path handling for modular GUI loading
Reworked moved windows to use more self-contained path and config handling
Removed several direct dependencies on ROOT, DEFAULT_CASE_ROOT, and other main-file-only helpers
Fixed post-refactor dynamic analysis execution issue caused by config save handling
Improved maintainability and reduced risk for future GUI enhancements
Why v1.5 matters

While v1.4 expanded functionality and polished workflows, v1.5 strengthens the foundation of the project itself. This release is about making RingForge Workbench easier to evolve. By separating major GUI components into focused modules, future improvements such as additional windows, shared helper libraries, better launcher separation, and cleaner testing paths can be implemented with less risk and less code duplication.

Next planned direction
Move shared GUI helper functions into gui/gui_utils.py
Move the main App class into gui/main_app.py
Reduce scripts/static_triage_gui.py to a thin launcher
Continue improving maintainability without disrupting stable workflows

## What’s New in v1.4

RingForge Workbench v1.4 focuses on analysis quality, false-positive reduction, stronger trust-signal handling, and a major hardening of the API Spec Analysis experience. This release improves static confidence, dynamic signal quality, endpoint and auth visibility for API specs, GUI polish, and exported HTML reporting.

### v1.4 Highlights

- Reduced noisy dynamic-analysis scoring for benign applications
- Improved digital signature detection and verification handling
- Added configurable capa timeout support
- Added configurable capa large-file skip behavior for very large binaries
- Improved 7-Zip discovery and extraction handling on Windows
- Fixed YARA rules integration and reporting
- Strengthened API Spec Analysis with richer endpoint risk context
- Added top risky endpoints and recommended testing guidance
- Improved auth inheritance, auth source display, and endpoint risk visibility
- Improved API Spec Analysis GUI layout and HTML reporting
- Continued overall workflow polish across RingForge Workbench

### v1.4 Changelog

#### Static Analysis
- Improved Authenticode signature handling and reduced false unsigned results
- Improved signature reporting and verification accuracy
- Added configurable capa timeout support
- Added configurable capa max-size skip behavior for very large binaries
- Improved handling of large benign software that previously caused long capa timeouts
- Improved 7-Zip resolution on Windows by supporting common install locations
- Fixed YARA path/rules handling and verified rule execution in reports
- Continued static reporting and scoring refinement

#### Dynamic Analysis
- Reduced noisy dynamic verdicting for benign applications
- Improved filtering of analyzer-generated artifacts from dynamic findings
- Reduced Defender-related and environmental noise in dynamic scoring
- Lowered weight of generic runtime activity such as normal process and network volume
- Improved emphasis on stronger signals such as persistence and higher-risk behavior
- Improved dynamic scoring so benign baseline applications no longer over-score unnecessarily
- Improved dynamic report readability and result quality for large GUI applications

#### API Spec Analysis
- Improved endpoint inventory and spec parsing workflow
- Added richer endpoint risk scoring and endpoint-level risk context
- Improved auth handling, including inherited/global auth behavior
- Added auth source visibility in the UI
- Added risk level visibility in the endpoint inventory
- Added top risky endpoints section
- Added recommended tests section for analyst follow-up
- Improved handling of risky, broken, and partially incomplete API specs
- Improved display of public versus authenticated endpoints
- Improved API Spec Analysis GUI layout and usability
- Improved HTML reporting for spec analysis to match GUI enhancements
- Improved analyst-facing context for insecure servers, risky routes, destructive methods, uploads, and sensitive parameters

#### GUI / Reporting
- Improved API Spec Analysis window layout and presentation
- Added better use of available screen space for spec-analysis review
- Improved endpoint inventory readability
- Improved report structure and exported HTML polish
- Continued refinement of RingForge branding, workflow clarity, and review usability

## v1.3 - API Spec Analysis Maturity Release

Version 1.3 turned API Spec Analysis into a practical, polished, and testable workflow. It improved specification parsing, report quality, output organization, and overall usability while preserving the platform’s static, dynamic, and combined scoring foundation.

### v1.3 Highlights

- Added a redesigned API Spec Analysis workspace
- Improved support for OpenAPI 3.x and Swagger 2.0 specifications
- Added structured endpoint inventory reporting
- Added polished HTML report generation for spec analysis
- Improved authentication parsing and normalization
- Improved per-endpoint authentication reporting
- Improved report naming using the analyzed specification name
- Added spec-specific latest report handling
- Continued GUI polish and workspace consistency improvements

### v1.3 Changelog

- Added overview metrics and improved endpoint inventory layout
- Improved API Spec Analysis dashboard structure and usability
- Improved OpenAPI 3.x and Swagger 2.0 parsing support
- Added endpoint inventory reporting with method, path, summary, auth, parameter count, and flags
- Added polished HTML reporting for API spec analysis
- Improved authentication normalization and endpoint-level auth visibility
- Improved report naming using specification file names
- Added spec-specific latest-report handling for easier reopening of the correct report
- Continued GUI refinement and workflow presentation cleanup across RingForge Workbench

## v1.2 - RingForge Workbench Rebrand

Version 1.2 marked the transition from the project’s earlier analyzer-focused identity into **RingForge Workbench**.

This release focused on branding, presentation, GUI polish, and overall platform direction rather than major new feature expansion. It established a cleaner project identity and prepared the foundation for the more mature API Spec Analysis and reporting improvements delivered in **v1.3** and expanded further in **v1.4**.

### v1.2 Changes

- Rebranded the project as **RingForge Workbench**
- Updated repository, README, and release naming
- Improved visual consistency and overall presentation
- Continued GUI polish and usability refinement
- Established a broader workbench-style platform identity for future growth

## Current Version Position

### v1.1

Scoring and workflow milestone release:

- Combined scoring across Static, Dynamic, and Spec/API workflows
- Presence-aware GUI score display
- Dynamic and Spec case-based score regeneration
- Progress final-state and optional helper-tool `n/a` handling

### v1.2

GUI polish and platform identity release:

- Rebrand to RingForge Workbench
- Visual cleanup and consistency improvements
- Simplified workflow presentation
- Better spacing, button styling, and layout behavior
- Foundation for broader platform growth

### v1.3

API Spec Analysis feature maturity release:

- Polished API Spec Analysis workspace
- OpenAPI and Swagger spec parsing improvements
- Endpoint inventory and HTML spec reporting
- Auth normalization and per-endpoint auth reporting
- Improved report naming and report-open behavior
- Additional GUI refinement and workspace consistency improvements

### v1.4

Analysis quality and false-positive reduction release:

- Dynamic scoring tuned to reduce environmental and benign-runtime noise
- Signature verification handling improved for valid signed software
- Capa timeout and large-file skip support added for heavy binaries
- YARA integration and report visibility improved
- API Spec Analysis hardened with richer endpoint risk context
- Top risky endpoints and recommended tests added
- Auth inheritance, auth source, and endpoint risk display improved
- API Spec Analysis GUI and HTML reporting significantly polished

## Planned Next Iteration

Future work after v1.4 may include:

- cumulative API spec scoring across multiple test runs
- final multi-test assessment summaries
- expanded API spec risk scoring and weighting
- additional report presentation options
- continued cleanup of advanced utilities and developer-focused workflows
- richer combined reporting across static, dynamic, and spec-based results

## Outputs

### Static case outputs

A typical static case folder may contain:

```text
cases/<case>/
  analysis.log
  api_analysis.json
  capa.json
  capa.txt
  extracted/
  extracted_manifest.json
  file.txt
  iocs.csv
  iocs.json
  lief_metadata.json
  pe_metadata.json
  report.html
  report.md
  report.pdf
  runlog.json
  signing.json
  strings.txt
  subfiles/
  summary.json
  virustotal.json
```

On some environments, `report.pdf` may not be generated. In that case, open `report.html` and use your browser’s Print to PDF option.

### Dynamic case artifacts

A dynamic-analysis run can produce a structure like:

```text
cases/<case_name>/
  metadata/
    run_config.json
    sample_info.json
    run_summary.json
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
  files/
    dropped_files.json
    dropped_files_summary.json
  reports/
    dynamic_findings.json
    dynamic_report.html
    dynamic_report.pdf
```

### API Spec case artifacts

An API Spec Analysis run can produce a structure like:

```text
cases/<case_name>/
  spec/
    spec_inventory_<spec_name>_<timestamp>.json
    spec_inventory_<spec_name>_<timestamp>.html
    spec_inventory_latest_<spec_name>.json
    spec_inventory_latest_<spec_name>.html
    spec_inventory_latest.json
    spec_inventory_latest.html
    original_<spec_name>.yaml
```

### Artifact purpose

- `run_config.json` — execution settings used for the run
- `sample_info.json` — sample hashes, size, and metadata
- `run_summary.json` — final summarized run output
- `parsed_events.json` — normalized Procmon event data
- `interesting_events.json` — reduced high-value Procmon events
- `task_diffs.json` — before/after scheduled task changes
- `service_diffs.json` — before/after Windows service changes
- `dropped_files.json` — candidate dropped-file details
- `dynamic_findings.json` — analyst-facing highlights and summaries
- `dynamic_report.html` — themed analyst-facing HTML report
- `dynamic_report.pdf` — PDF report when PDF backend is available
- `spec_inventory_<spec_name>_<timestamp>.json` — saved API spec analysis result for a specific run
- `spec_inventory_<spec_name>_<timestamp>.html` — analyst-facing HTML report for a specific spec run
- `spec_inventory_latest_<spec_name>.html` — latest named report for the currently analyzed spec
- `spec_inventory_latest.html` — generic latest spec report for compatibility and quick-open workflows

## Repo Layout

```text
ringforge-workbench/
  docs/
  scripts/
  static_triage_engine/
  dynamic_analysis/
    __init__.py
    orchestrator.py
    models.py
    procmon_runner.py
    procmon_parser.py
    dropped_file_triage.py
    findings.py
    html_report.py
    report_theme.py
    snapshot_tasks.py
    diff_tasks.py
    snapshot_services.py
    diff_services.py
    utils.py
  tools/
    procmon-configs/
  cases/                 # generated locally, usually gitignored
  logs/                  # generated locally, usually gitignored
  .gitignore
  LICENSE
  README.md
  requirements.txt
  triage_inbox.py
```

## Recommended Release Folder Layout

```text
RingForge_Workbench_v1.4/
  RingForgeWorkbench.exe
  scripts/
  static_triage_engine/
  dynamic_analysis/
  README.md
  LICENSE
```

## Development Roadmap

RingForge Workbench is being expanded from a static triage utility into a more complete multi-stage software analysis platform. The roadmap below outlines the planned direction for static, dynamic, API, scoring, and reporting capabilities.

### Current Capabilities
- Static analysis workflow with case-based output
- Dynamic analysis window and execution workflow
- API analysis window for manual request testing
- API Spec Analysis workflow for OpenAPI / Swagger definitions
- HTML reporting for static, dynamic, and API spec analysis
- Organized case folder structure for saved artifacts and reports

### Near-Term Enhancements
- Security API presets for common enrichment services
  - VirusTotal
  - AbuseIPDB
  - urlscan
  - Shodan
- Raw JSON response saving for API tests
- Parsed API result summaries for faster triage
- Improved HTML export formatting for API analysis
- Auto-fill options using the selected sample, MD5, SHA1, or SHA256
- Multi-test API spec scoring and final summary workflows

### Unified Scoring and Assessment
- Separate scoring for each analysis area
  - Static Analysis Score
  - Dynamic Analysis Score
  - API / Intelligence Score
  - API Spec Analysis Score
- Combined weighted maliciousness score across completed modules
- Confidence rating based on analysis coverage
- Standardized verdict categories
  - Likely Benign
  - Low Suspicion
  - Suspicious
  - Malicious Likely
  - Highly Malicious
- Combined assessment output in JSON and HTML formats

### Analysis Improvements
- Stronger static suspiciousness heuristics
- Expanded dynamic behavior scoring
- Better IOC enrichment and reputation correlation
- Improved persistence and execution pattern detection
- Correlation between static findings, dynamic behavior, external intelligence, and API spec risk indicators

### Reporting Improvements
- Combined analyst report covering all completed modules
- Executive-style summary view
- Key findings and evidence summary sections
- Analyst notes section
- Easier export and case-deliverable workflow

### Planned Tooling
- File and hash lookup presets
- File upload presets for executables, DLLs, MSIs, and archives
- IOC-specific enrichment workflows for:
  - File
  - Hash
  - IP
  - Domain
  - URL
- API key validation and connectivity testing
- Automated chaining between enrichment tools

### Long-Term Goals
- Local YARA integration
- Certificate and signature trust analysis
- Entropy and packer detection improvements
- Expanded PE metadata scoring
- Multi-tool intelligence orchestration
- More advanced malware triage and recommendation engine

## Project Direction

The long-term goal is to evolve RingForge Workbench into a unified triage platform that can combine static artifacts, runtime behavior, API specifications, and external intelligence into a single assessment workflow. This will allow analysts to move from isolated test results to a more complete and defensible maliciousness determination.

This is the most reliable packaging model right now.

## Requirements

### Python

- Python 3.11 or 3.12 recommended

### Python packages

Typical dependencies include:

- `requests`
- `pefile`
- `lief`
- `pyyaml`
- `pyinstaller`
- `weasyprint` (optional for direct PDF generation)
- `pillow` (if using image-backed branding)
- any packages listed in `requirements.txt`

### Linux / WSL tools

Common external tools:

- `file`
- `strings`
- `osslsigncode`
- `cabextract`
- `p7zip-full`
- `binutils`

Optional:

- `innoextract`
- `msitools`
- `unar`

### Dynamic analysis tools

For dynamic analysis on Windows, Procmon is required for full runtime capture.

Typical setup:
- Procmon obtained separately from Microsoft Sysinternals
- optional Procmon config file under `tools/procmon-configs`
- a dedicated Windows VM for execution and observation
- administrative rights where required for capture and snapshotting

### capa resources

You should also have:

- `tools/capa-rules`
- `tools/capa/sigs`

## Windows Setup Example

```powershell
cd D:
ing_forge_analyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install lief
```

Optional PDF support:

```powershell
pip install weasyprint
```

If WeasyPrint dependencies are unavailable on Windows, HTML export still works and can be printed to PDF from the browser.

## Linux Setup Example

```bash
cd ~/analysis/ringforge-workbench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pefile pyyaml lief flare-capa
bash scripts/bootstrap_capa_rules.sh
```

## Running the GUI

### Windows

```powershell
cd D:
ing_forge_analyzer
.\.venv\Scripts\Activate.ps1
python .\scripts\static_triage_gui.py
```

### Linux

```bash
cd ~/analysis/ringforge-workbench
source .venv/bin/activate
python scripts/static_triage_gui.py
```

### Dynamic Analysis window

The GUI includes a separate Dynamic Analysis window with:

- sample path selection
- case folder selection
- timeout configuration
- Procmon path selection
- Procmon config selection
- Procmon enable/disable toggle
- live output pane
- phase/status progress messages
- findings summary output
- HTML report export
- browser-based PDF fallback

### API Spec Analysis window

The GUI includes a separate API Spec Analysis window with:

- spec file selection
- Overview metrics
- Summary and Risk Notes panels
- Top Risky Endpoints section
- Recommended Tests section
- Endpoint Inventory table
- HTML report generation
- Open Case Files and report-open actions
- OpenAPI 3.x and Swagger 2.0 support

## Running the CLI

Example help command:

```bash
python scripts/static_triage.py --help
```

Example analysis run:

```bash
python scripts/static_triage.py "/path/to/sample.exe"
```

## Packaging RingForge Workbench v1.4

### Build

Example PyInstaller build:

```bash
pyinstaller --onedir --windowed --name RingForgeWorkbench --paths . --collect-submodules dynamic_analysis scripts/static_triage_gui.py
```

### Release folder

Create the release folder and copy:

- built executable
- `scripts`
- `static_triage_engine`
- `dynamic_analysis`
- `README.md`
- `LICENSE`
- `requirements.txt` if needed

### Zip

```powershell
cd release
Compress-Archive -Path .\RingForge_Workbench_v1.4 -DestinationPath .\RingForge_Workbench_v1.4.zip -Force
```

## Release Notes – RingForge Workbench v1.4

### Added
- configurable capa timeout support
- configurable capa max-size skip behavior for very large binaries
- top risky endpoints for API spec analysis
- recommended test guidance for API spec analysis
- auth source visibility in API spec analysis
- risk level visibility in API spec endpoint inventory
- richer HTML reporting for API spec analysis
- unresolved ref awareness and parser-warning handling for spec-analysis workflows

### Improved
- digital signature verification and signed-file reporting
- dynamic scoring quality for benign applications
- filtering of analyzer-generated and environmental dynamic-analysis noise
- API spec auth inheritance and auth visibility
- API spec UI layout and analyst readability
- API spec HTML report structure and presentation
- YARA rules integration and report visibility
- 7-Zip discovery and Windows extraction handling
- GUI layout, spacing, branding, and consistency across RingForge Workbench

### Fixed
- false unsigned results for valid signed software
- noisy dynamic verdicting caused by benign process and network activity
- long capa delays for very large benign binaries
- API Spec Analysis health-route false positives
- endpoint auth display issues in API Spec Analysis
- API Spec Analysis latest-report usability and output clarity

## Troubleshooting

### 1. `api_analysis.json` is missing

Make sure:

- `static_triage_engine/api_analysis.py` exists
- `engine.py` imports and runs `analyze_apis()`
- `pefile` is installed in the active Python environment

Linux example:

```bash
source .venv/bin/activate
pip install pefile
```

### 2. API Analysis section says artifact not present

This usually means the analysis ran with an older `engine.py` that did not yet call the API analysis step, or the case folder was generated before the feature was added.

Use a fresh case name and rerun.

### 3. Signing looks wrong for a valid signed file

Clear the signing cache and rerun so the updated signing parser can re-evaluate the sample:

```bash
rm -f logs/signing_cache.json
```

### 4. Dynamic window opens but no run starts

Check that:

- the GUI worker thread is starting correctly
- the sample path is valid
- the case path is writable
- Procmon path is valid if Procmon capture is enabled

### 5. Procmon capture fails

Check:

- Procmon is present at the configured path
- Procmon is not already running in a conflicting session
- the analysis is being performed in a Windows environment with required permissions

### 6. Scheduled task or service snapshots fail

Check:

- PowerShell is available
- the process has sufficient rights to query scheduled tasks and services
- temporary JSON output can be written successfully

### 7. capa fails or is skipped

Check:

- `tools/capa-rules` exists
- `tools/capa/sigs` exists
- capa is installed in the active virtual environment

For very large binaries, RingForge Workbench may intentionally skip capa based on the configured size threshold.

### 8. LIEF fails

Make sure LIEF is installed in the active virtual environment:

```bash
pip install lief
```

### 9. VirusTotal lookup fails

Common reasons:

- `VT_API_KEY` is not set
- network/DNS failure
- rate limit or API response issue

### 10. HTML report exports but PDF does not

If the HTML report is created successfully but PDF generation fails on Windows, WeasyPrint system dependencies are likely missing. Open the HTML report in your browser and use Print → Save as PDF.

### 11. API Spec Analysis rejects a file

API Spec Analysis only supports:
- `.json`
- `.yaml`
- `.yml`

Make sure the selected file is an OpenAPI or Swagger definition in one of those formats.

### 12. Paths fail in Linux

Use Linux-style paths in the GUI, not Windows paths.

## Safety Notes

- dynamic analysis should only be performed inside an isolated, revertible Windows VM or other controlled sandbox
- do not run unknown samples on a personal daily-use host
- Procmon-backed execution and persistence snapshotting can generate significant host noise on non-isolated systems
- legitimate software can still contain powerful APIs, installer behaviors, or autorun-related logic; scoring and findings should always be reviewed in context
- API spec analysis can highlight risky routes, methods, auth patterns, and follow-up test ideas, but findings still require analyst review in context

## Notes

- API analysis currently applies to Windows PE executables and DLLs through import/API-chain analysis
- API Spec Analysis currently supports OpenAPI and Swagger definition files in JSON or YAML form
- dynamic analysis in RingForge Workbench v1.4 is intended as a practical triage layer, not a full sandbox replacement
- future work may include cumulative spec scoring, final multi-test summaries, tighter Procmon filtering, cleaner VM-first tuning, installer-monitor expansion, and broader behavior correlation

## License

See `LICENSE`.
