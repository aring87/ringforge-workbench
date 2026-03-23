# RingForge Workbench is a Static and Dynamic Software Analysis Platform

**Static insight. Dynamic visibility.**

**RingForge Workbench** is a unified software triage platform designed for static, dynamic, and behavioral analysis, scoring, and reporting.

The project brings together multiple analysis methods into a single workflow to support efficient triage, structured outputs, and future expansion into a broader software analysis workbench.

## Current Release
**Version:** v1.3

## Overview

RingForge Workbench is designed to help analysts quickly triage Windows software samples such as EXE, DLL, installer, launcher, and related package files. It combines metadata extraction, strings analysis, capa behavior analysis, IOC extraction, signing validation, VirusTotal reputation, executable API import analysis, controlled dynamic runtime behavior collection, and API specification analysis into a single workflow.

The platform creates case-based output for each workflow and produces structured artifacts such as JSON analysis files, IOC exports, Markdown and HTML reports, PDF reports when supported, Procmon-derived runtime artifacts, persistence diffs, dynamic findings summaries, and API spec inventory reports.

## What’s New in v1.3

RingForge Workbench v1.3 builds on the v1.2 GUI polish milestone by turning **API Spec Analysis** into a practical, polished, and testable analysis workflow. This release improves the API spec parsing experience, reporting quality, output organization, and overall usability while preserving the existing static, dynamic, and combined scoring foundations.

## v1.2 - RingForge Workbench Rebrand

Version 1.2 marked the project transition from **RingForge Analyzer** to **RingForge Workbench**.

This release focused on identity, presentation, and platform direction rather than major new analysis capability. The goal of v1.2 was to establish a cleaner product name, improve overall polish, and set the foundation for future feature growth.

### v1.2 Highlights

- Rebranded the project from **RingForge Analyzer** to **RingForge Workbench**
- Updated naming across the repository, documentation, and release materials
- Continued GUI polish and workflow refinement
- Prepared the platform for the expanded analysis improvements delivered in **v1.3**

### Why v1.2 Mattered

v1.2 was the transition point that turned the project into a broader workbench-style platform instead of a narrowly named analyzer. It created the foundation for the more mature API Spec Analysis improvements, reporting enhancements, and workspace refinements that followed in **v1.3**.

### Changes
- Renamed project branding to **RingForge Workbench**
- Updated repository, README, and release naming
- Aligned product identity with static, dynamic, and behavioral analysis capabilities
- Established a broader platform identity for future growth

### Core Improvements
- Added a redesigned **API Spec Analysis** workspace
- Added improved **OpenAPI 3.x** and **Swagger 2.0** support
- Added structured **endpoint inventory** reporting
- Added polished **HTML report generation** for spec analysis
- Improved **authentication parsing and normalization**
- Improved **per-endpoint authentication visibility**
- Improved **report naming** using the analyzed spec filename
- Added **spec-specific latest report handling**
- Continued overall GUI polish and workspace consistency

### API Spec Analysis Workspace
- Reworked the API Spec Analysis window into a cleaner dashboard layout
- Added Overview metrics for:
  - Format
  - Version
  - Endpoint count
  - Authentication summary
- Added a split-pane workspace with:
  - Summary
  - Risk Notes
  - Getting Started guidance
  - Endpoint Inventory
- Improved default window sizing and layout balance
- Improved scrollbar handling, column layout, and table presentation

### API Spec Parsing and Reporting
- Confirmed working support for:
  - OpenAPI 3.x YAML and JSON
  - Swagger 2.0 YAML and JSON
- Added endpoint inventory reporting with:
  - method
  - path
  - summary
  - auth
  - parameter count
  - flags
- Added HTML report generation for API spec analysis
- Improved report filenames to include the analyzed spec name and timestamp
- Added spec-specific “latest” report handling for easier reopening of the correct report
- Preserved generic latest-report behavior for compatibility with existing report-open workflows

### Authentication Parsing Improvements
- Normalized authentication scheme names for cleaner reporting
- Removed duplicate auth labels caused by mixed naming variants
- Improved endpoint-level auth visibility so endpoints display their effective auth instead of inheriting the full global auth summary
- Cleaned output for:
  - public / unauthenticated endpoints
  - bearer auth
  - api-key auth
  - basic auth
- Improved Swagger 2.0 auth handling consistency

### GUI and UX Improvements
- Continued cleanup of the main RingForge Workbench interface
- Improved branding and workspace presentation
- Improved results layout and readability
- Improved output and report access flow
- Improved API Spec Analysis button layout, table behavior, and report-opening experience

## Current Version Position

### v1.1
Scoring and workflow milestone release:
- Combined scoring across Static, Dynamic, and Spec/API
- Presence-aware GUI score display
- Dynamic and Spec case-based score regeneration
- Progress final-state and optional helper-tool `n/a` handling

### v1.2
GUI polish and usability refinement release:
- Visual cleanup and consistency improvements
- Simplified workflow presentation
- Updated Dynamic Analysis and API Spec Analysis windows
- Better spacing, button styling, and layout behavior

### v1.3
API Spec Analysis feature maturity release:
- Polished API Spec Analysis workspace
- OpenAPI and Swagger spec parsing improvements
- Endpoint inventory and HTML spec reporting
- Auth normalization and per-endpoint auth reporting
- Improved report naming and report-open behavior
- Additional GUI refinement and workspace consistency improvements

## Planned Next Iteration
Future work after v1.3 may include:
- cumulative API spec scoring across multiple test runs
- final multi-test assessment summaries
- expanded API spec risk scoring and weighting
- additional report presentation options
- continued cleanup of advanced utilities and developer-focused workflows

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
RingForge_Workbench_v1.3/
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
cd D:\ring_forge_analyzer
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
cd D:\ring_forge_analyzer
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

## Packaging RingForge Workbench v1.3

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
Compress-Archive -Path .\RingForge_Workbench_v1.3 -DestinationPath .\RingForge_Workbench_v1.3.zip -Force
```

## Release Notes – RingForge Workbench v1.3

### Added
- redesigned API Spec Analysis workspace
- Overview metrics for spec parsing
- endpoint inventory reporting
- HTML report generation for API spec analysis
- OpenAPI 3.x and Swagger 2.0 validation coverage
- spec-specific latest report naming and access behavior

### Improved
- authentication normalization and per-endpoint auth reporting
- API spec HTML report readability
- GUI layout, spacing, branding, and consistency
- report naming using analyzed spec filenames
- report-open behavior for spec-specific latest reports

### Fixed
- API Spec Analysis window layout and rendering issues
- endpoint inventory spacing and scrollbar behavior
- incorrect global-auth display on public endpoints
- duplicate auth naming variants in spec analysis results
- Swagger 2.0 type labeling

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

### 7. capa fails

Check:

- `tools/capa-rules` exists
- `tools/capa/sigs` exists
- capa is installed in the active virtual environment

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
- API spec analysis can highlight risky routes, methods, and auth patterns, but findings still require analyst review in context

## Notes

- API analysis currently applies to Windows PE executables and DLLs through import/API-chain analysis
- API Spec Analysis currently supports OpenAPI and Swagger definition files in JSON or YAML form
- dynamic analysis in RingForge Workbench v1.3 is intended as a practical triage layer, not a full sandbox replacement
- future work may include cumulative spec scoring, final multi-test summaries, tighter Procmon filtering, cleaner VM-first tuning, installer-monitor expansion, and broader behavior correlation

## License

See `LICENSE`.
