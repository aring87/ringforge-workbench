# RingForge Analyzer — Static and Dynamic Software Analysis Platform

**Static insight. Dynamic visibility.**

RingForge Analyzer is a malware/software analysis toolkit for Windows executables and installers that supports both **static triage** and early-stage **dynamic behavior analysis**. It generates structured case artifacts, IOC output, persistence-diff data, dropped-file triage results, signing results, API behavior analysis, and analyst-facing reports for triage, training, and investigation.

**Current release: v1.1**

## Overview

RingForge Analyzer is designed to help analysts quickly triage Windows software samples such as EXE, DLL, installer, launcher, and related package files. It combines metadata extraction, strings analysis, capa behavior analysis, IOC extraction, signing validation, VirusTotal reputation, executable API import analysis, and controlled dynamic runtime behavior collection into a single workflow.

The pipeline creates a case folder for each run and produces structured outputs such as JSON artifacts, CSV IOC files, Markdown and HTML reports, PDF reports when supported, Procmon-derived runtime artifacts, persistence diffs, and dynamic findings summaries.

## What’s New in RingForge Analyzer v1.1

RingForge Analyzer v1.1 expands the platform beyond basic hybrid static + dynamic triage and introduces a more complete analyst workflow for scoring, runtime review, and API/spec-driven assessment.

### Highlights

- separate Dynamic Analysis GUI window
- separate Spec Analysis GUI window
- Procmon-backed dynamic capture workflow
- dynamic HTML report export
- browser-based PDF fallback workflow
- Procmon configuration file support
- improved dynamic findings noise reduction
- improved progress and status wording for optional steps
- optional Windows-missing tools now display as `n/a` where appropriate
- combined Static / Dynamic / Spec scoring
- individual-only scoring support for Static-only, Dynamic-only, and Spec-only runs
- main-window score breakdown for Static / Dynamic / Spec
- case-based combined score generation from saved analysis artifacts
- Spec Analysis scoring integration for risky API design patterns
- early UI theming updates aligned to report styling

## Core Capabilities

### Static Analysis

- file hashing
- PE metadata extraction
- LIEF metadata extraction
- optional payload extraction
- optional file type classification
- optional strings extraction
- capa capability analysis
- IOC extraction
- VirusTotal hash reputation lookup
- static scoring and verdict support

### Dynamic Analysis

- Procmon-backed runtime collection
- process creation visibility
- file write visibility
- network event visibility
- suspicious path detection
- scheduled task diffing
- service diffing
- dropped file review
- dynamic findings summary
- dynamic HTML reporting
- dynamic scoring support

### Spec Analysis

RingForge Analyzer includes an API specification analysis workflow for OpenAPI/Swagger-style specs.

This feature:

- parses YAML and JSON API specifications
- builds endpoint inventory views
- summarizes methods, paths, parameters, and auth visibility
- identifies risky design patterns such as:
  - missing authentication
  - admin/internal-like routes
  - destructive methods on sensitive routes
  - file upload endpoints
- writes structured spec analysis artifacts to the case folder
- contributes to the Spec/API score in the main summary
- supports combined scoring with Static and Dynamic analysis results

### API Analysis

- request-based API testing workflow
- saved response and report output
- API-specific output review
- integration path from Spec Analysis into API testing workflows

## Scoring Model

RingForge Analyzer supports both individual and combined scoring modes.

### Individual scoring

Each analysis mode can be scored independently:

- Static-only run → Static score is populated
- Dynamic-only run → Dynamic score is populated
- Spec-only run → Spec/API score is populated

### Combined scoring

When multiple analysis types are present in the same case, RingForge Analyzer generates a combined score using all available evidence.

Examples:

- Static-only case → Combined score equals Static score
- Dynamic-only case → Combined score equals Dynamic score
- Spec-only case → Combined score equals Spec/API score
- Full case → Combined score reflects Static + Dynamic + Spec/API

### Presence-aware display

Analysis categories that were not run are shown as `—` in the GUI instead of `0`, making it easier to distinguish between:

- not run
- run with low or no scoring contribution

## Reputation and Scoring

RingForge Analyzer now supports:

- VirusTotal hash lookup
- verdict classification
- static risk scoring
- dynamic behavior scoring
- spec/API risk scoring
- combined score generation from available case artifacts
- installer and launcher-aware false-positive reduction
- presence-aware score display for partial workflows

## GUI Workflow Notes

- Static, Dynamic, and Spec analysis can be run independently
- combined scoring updates from saved case artifacts
- not-run sections display as `—`
- optional helper tools that are unavailable on Windows may display as `n/a`
- `n/a` is used to distinguish unsupported or unavailable optional tools from true processing failures

## Current v1.1 Position

RingForge Analyzer v1.1 should be considered the scoring and workflow milestone release.

This version establishes:

- individual scoring by analysis type
- combined scoring across all present artifacts
- improved case-based workflow behavior
- dynamic and spec integration into the main summary
- a stronger analyst-facing GUI workflow for hybrid software assessment

## Planned Next Iteration

The next polish-focused release is planned as **v1.2** and will focus on:

- additional GUI polish
- layout cleanup
- workflow refinement
- further quality-of-life improvements
- small presentation and usability enhancements

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
