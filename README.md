# RingForge Analyzer — Static and Dynamic Software Analysis Platform

**Static insight. Dynamic visibility.**

RingForge Analyzer is a malware/software analysis toolkit for Windows executables and installers that supports both **static triage** and early-stage **dynamic behavior analysis**. It generates structured case artifacts, IOC output, persistence-diff data, dropped-file triage results, signing results, API behavior analysis, and analyst-facing reports for triage, training, and investigation.

**Current release: v1.2**

## Overview

RingForge Analyzer is designed to help analysts quickly triage Windows software samples such as EXE, DLL, installer, launcher, and related package files. It combines metadata extraction, strings analysis, capa behavior analysis, IOC extraction, signing validation, VirusTotal reputation, executable API import analysis, and controlled dynamic runtime behavior collection into a single workflow.

The pipeline creates a case folder for each run and produces structured outputs such as JSON artifacts, CSV IOC files, Markdown and HTML reports, PDF reports when supported, Procmon-derived runtime artifacts, persistence diffs, and dynamic findings summaries.

## What’s New in v1.2

RingForge Analyzer v1.2 builds on the v1.1 scoring and workflow milestone with a focused GUI polish and usability refinement release. This version improves visual consistency, simplifies the main workflow, and standardizes the experience across the main GUI, Dynamic Analysis, and API Spec Analysis windows.

### Core Improvements
- Refined the main GUI layout so the output panel is visible on launch
- Improved button styling for a cleaner, more professional dark-theme interface
- Standardized Browse and Clear buttons to better match entry-field layout
- Tightened action-row spacing and improved right-side status alignment
- Kept the v1.1 combined and individual scoring model intact across Static, Dynamic, and Spec/API analysis

### Main GUI Updates
- Output area is now visible immediately when the application opens
- Main action row was cleaned up and spaced more consistently
- API and Spec entry on the primary workflow were simplified into a single **API Spec Analysis** path
- Buttons were updated for better consistency, sizing, and visual balance
- Supporting Browse/Clear controls now align better with adjacent input fields

### Dynamic Analysis Window Updates
- Reworked to better match the main GUI theme and layout
- Grouped settings into a cleaner **Dynamic Analysis Settings** section
- Moved **Enable Procmon Capture** next to timeout controls for a more logical workflow
- Simplified the action row to the most useful core actions:
  - Run Dynamic Analysis
  - Open Case Folder
  - Open Latest Report
- Removed the redundant export button from the primary action row
- Improved right-side Browse button sizing and alignment
- Preserved live output and case-based scoring refresh behavior

### API Spec Analysis Updates
- Renamed and positioned as the primary spec-based API workflow
- Updated layout for clearer structure and better consistency with the rest of the application
- Organized results into:
  - Summary
  - Risk Notes
  - Endpoint Inventory
- Improved top action row styling and naming
- API spec results continue to save into the case `spec` folder and feed the combined scoring workflow

### API Testing Positioning
- Manual live API request testing remains a separate advanced utility
- The primary workflow is now centered on **API Spec Analysis**
- This keeps the main GUI focused while preserving flexibility for deeper API request testing when needed

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

## Planned Next Iteration
Future work after v1.2 may include:
- Additional UI refinements and spacing cleanup
- Optional primary/secondary button hierarchy improvements
- Expanded report presentation options
- Continued cleanup of advanced utilities and developer-focused workflows

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

## Repo Layout

```text
RingForge-Analyzer/
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
RingForge_Analyzer_v1.1/
  RingForgeAnalyzer.exe
  scripts/
  static_triage_engine/
  dynamic_analysis/
  README.md
  LICENSE
```
## Development Roadmap

RingForge Analyzer is being expanded from a static triage utility into a more complete multi-stage software analysis platform. The roadmap below outlines the planned direction for static, dynamic, API, scoring, and reporting capabilities.

### Current Capabilities
- Static analysis workflow with case-based output
- Dynamic analysis window and execution workflow
- API analysis window for manual request testing
- HTML reporting for static and API analysis
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

### Unified Scoring and Assessment
- Separate scoring for each analysis area
  - Static Analysis Score
  - Dynamic Analysis Score
  - API / Intelligence Score
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
- Correlation between static findings, dynamic behavior, and external intelligence

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
The long-term goal is to evolve RingForge Analyzer into a unified triage platform that can combine static artifacts, runtime behavior, and external intelligence into a single assessment workflow. This will allow analysts to move from isolated test results to a more complete and defensible maliciousness determination.

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
cd ~/analysis/RingForge-Analyzer
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
python .\scripts\static_triage_gui_v10.py
```

### Linux

```bash
cd ~/analysis/RingForge-Analyzer
source .venv/bin/activate
python scripts/static_triage_gui_v10.py
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

## Running the CLI

Example help command:

```bash
python scripts/static_triage.py --help
```

Example analysis run:

```bash
python scripts/static_triage.py "/path/to/sample.exe"
```

## Packaging RingForge Analyzer v1.1

### Build

Example PyInstaller build:

```bash
pyinstaller --onedir --windowed --name RingForgeAnalyzer --paths . --collect-submodules dynamic_analysis scripts/static_triage_gui_v10.py
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
Compress-Archive -Path .\RingForge_Analyzer_v1.1 -DestinationPath .\RingForge_Analyzer_v1.1.zip -Force
```

## Release Notes – RingForge Analyzer v1.1

### Added

- dynamic HTML report export
- browser-open workflow for reviewing dynamic reports
- browser-based PDF fallback workflow
- Procmon configuration file support
- shared dark/blue HTML report theme foundation
- improved dynamic GUI controls for report actions

### Improved

- dynamic findings noise reduction on non-isolated hosts
- cleaner dynamic findings presentation
- better handling for optional or non-applicable analysis steps
- initial GUI theming work aligned to report styling

### Fixed

- report export path resolution for dynamic runs
- issues caused by duplicate or broken Dynamic Analysis helper methods
- improved report button integration inside the Dynamic Analysis window

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

### 11. Paths fail in Linux

Use Linux-style paths in the GUI, not Windows paths.

## Safety Notes

- dynamic analysis should only be performed inside an isolated, revertible Windows VM or other controlled sandbox
- do not run unknown samples on a personal daily-use host
- Procmon-backed execution and persistence snapshotting can generate significant host noise on non-isolated systems
- legitimate software can still contain powerful APIs, installer behaviors, or autorun-related logic; scoring and findings should always be reviewed in context

## Notes

- API analysis currently applies to Windows PE executables and DLLs through import/API-chain analysis
- dynamic analysis in RingForge Analyzer v1.1 is intended as a practical triage layer, not a full sandbox replacement
- future work may include a dedicated API Analysis window, tighter Procmon filtering, cleaner VM-first tuning, installer-monitor expansion, and broader behavior correlation

## License

See `LICENSE`.
