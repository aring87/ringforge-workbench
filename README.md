# Static Software / Malware Analysis — Static + Dynamic Analysis Pipeline

A malware/software analysis toolkit for Windows executables and installers that supports both **static triage** and early-stage **dynamic behavior analysis**. The project generates structured case artifacts, IOC output, persistence-diff data, dropped-file triage results, signing results, API behavior analysis, and analyst-facing reports for triage, training, and investigation.

## Overview

This project is designed to help analysts quickly triage Windows software samples such as EXE, DLL, installer, launcher, and related package files. It combines metadata extraction, strings analysis, capa behavior analysis, IOC extraction, signing validation, VirusTotal reputation, executable API import analysis, and dynamic runtime behavior collection into a single workflow.

The pipeline creates a case folder for each run and produces structured outputs such as JSON artifacts, CSV IOC files, Markdown and HTML reports, PDF reports when supported, Procmon-derived runtime artifacts, persistence diffs, and dynamic findings summaries.

## What’s New in v5

Version 5 expands the project from a static triage pipeline into a hybrid **static + dynamic analysis** platform.

### Highlights

- Procmon-backed dynamic capture
- parsed Procmon CSV output and normalized event JSON
- interesting-event filtering for high-value runtime activity
- dropped-file candidate triage
- scheduled task snapshotting and diffing
- Windows service snapshotting and diffing
- analyst-facing dynamic findings summaries
- separate Dynamic Analysis GUI window
- live phase/status updates during dynamic runs

## Core Features

### Static file triage

- MD5, SHA1, and SHA256 hashing
- `file` signature identification
- strings extraction
- PE metadata extraction
- LIEF metadata extraction
- IOC extraction
- capa analysis

### Signing validation

- Authenticode verification via `osslsigncode`
- verified timestamp handling
- signer subject and issuer extraction
- signing cache support
- improved parser handling for valid signed files

### Reputation and scoring

- VirusTotal hash lookup
- verdict classification
- risk scoring with benign-context dampening
- installer and launcher-aware false-positive reduction

### Executable API analysis

- imported DLL and API extraction
- API behavior category mapping
- API behavior chain detection
- `api_analysis.json` artifact generation
- report integration
- light API-chain scoring support

### Dynamic analysis

- Procmon-backed runtime capture
- Procmon CSV export
- normalized Procmon JSON parsing
- interesting-event filtering
- dropped-file candidate triage
- scheduled task snapshotting and diffing
- Windows service snapshotting and diffing
- analyst-facing findings summaries
- live GUI status output during dynamic runs

### Reporting

- Markdown report
- HTML report
- PDF report when environment supports it
- structured summary and runlog outputs
- dynamic findings output
- persistence diff outputs

### Extraction support

- embedded payload extraction
- recursive extraction support
- extracted payload manifest
- optional extracted PE subfile triage

## API Analysis

Executable API import analysis is supported for Windows PE files.

This feature:

- extracts imported DLLs and API functions
- groups APIs into behavior categories
- detects API behavior chains such as:
  - possible process injection
  - possible service installation
  - possible registry persistence
  - possible memory execution
- writes results to `api_analysis.json`
- includes findings in the Markdown and HTML reports

API-chain findings can contribute lightly to the final risk score. For trusted benign contexts such as signed clean installers or launchers, API-chain impact is automatically dampened so legitimate software is less likely to be over-scored.

## Dynamic Analysis

The project now includes an early-stage dynamic-analysis pipeline focused on practical analyst visibility rather than full sandbox emulation.

### Current capabilities

- build per-sample case folders
- collect sample metadata and hashes
- start and stop Procmon capture
- export Procmon CSV data
- parse Procmon CSV into structured JSON
- generate filtered interesting-event output
- triage dropped-file candidates from suspicious or user-writable paths
- snapshot and diff scheduled tasks
- snapshot and diff Windows services
- generate analyst-facing findings summaries
- display live phase/status updates in the GUI

### Recommended workflow

1. Run inside an isolated Windows 11 VM
2. Test first with a simple benign executable
3. Test with a small benign installer
4. Then test the target installer or sample
5. Review findings, persistence diffs, dropped files, and Procmon summaries

### Current limitations

- host-side background activity can create significant noise when run on a personal workstation
- Procmon filtering is still intentionally conservative
- dynamic analysis is designed as a practical triage layer, not a full malware sandbox replacement

## Typical Workflow

### Static workflow

1. Select a Windows executable, DLL, installer, or launcher
2. Create a new case name
3. Run static triage
4. Review:
   - signing results
   - VirusTotal summary
   - capa findings
   - API Analysis
   - IOC output
   - final score and verdict
5. Export or archive the case folder

### Dynamic workflow

1. Open the Dynamic Analysis window from the GUI
2. Select a sample path
3. Select or create a case folder
4. Set timeout and Procmon options
5. Run dynamic analysis
6. Review:
   - highlights
   - top written paths
   - top network processes
   - scheduled task diffs
   - service diffs
   - dropped-file output
   - final dynamic summary

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

## Repo Layout

```text
Static-Software-Malware-Analysis/
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
    snapshot_tasks.py
    diff_tasks.py
    snapshot_services.py
    diff_services.py
    utils.py
  tools/
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
Static_Software_Malware_Analysis_v5/
  Static_Software_Malware_Analysis_v5.exe
  scripts/
  static_triage_engine/
  dynamic_analysis/
  README.md
  LICENSE
```

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
- a dedicated Windows VM for execution and observation
- administrative rights where required for capture and snapshotting

### capa resources

You should also have:

- `tools/capa-rules`
- `tools/capa/sigs`

## Linux Setup Example

```bash
cd ~/analysis/Static-Software-Malware-Analysis
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pefile pyyaml lief flare-capa
bash scripts/bootstrap_capa_rules.sh
```

## Running the GUI

```bash
cd ~/analysis/Static-Software-Malware-Analysis
source .venv/bin/activate
python scripts/static_triage_gui_v10.py
```

### Dynamic Analysis window

The GUI includes a separate Dynamic Analysis window with:

- sample path selection
- case folder selection
- timeout configuration
- Procmon path selection
- Procmon enable/disable toggle
- live output pane
- phase/status progress messages
- findings summary output

## Running the CLI

Example help command:

```bash
python scripts/static_triage.py --help
```

Example analysis run:

```bash
python scripts/static_triage.py "/path/to/sample.exe"
```

## Packaging Version 5

### Build

Example PyInstaller build:

```bash
pyinstaller --onedir --windowed --name Static_Software_Malware_Analysis_v5 --paths . --collect-submodules dynamic_analysis scripts/static_triage_gui_v10.py
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

```bash
cd release
zip -r Static_Software_Malware_Analysis_v5.zip Static_Software_Malware_Analysis_v5
```

## Release Notes – v5.0

This release expands the project from a static triage pipeline into a hybrid static + dynamic analysis platform. It introduces the first major dynamic-analysis workflow for behavioral capture, persistence-change detection, dropped-file triage, and analyst-facing findings.

### Added

- dedicated `dynamic_analysis` package
- Procmon-backed dynamic capture workflow
- Procmon CSV parsing and normalized JSON output
- interesting-event filtering
- dropped-file candidate triage
- scheduled task snapshotting and diffing
- Windows service snapshotting and diffing
- analyst-facing findings summaries
- separate Dynamic Analysis GUI window
- live phase/status updates during runs

### Improved

- cleaner dynamic case structure under metadata, procmon, persistence, files, and reports
- more useful GUI output with highlights, task/service diff summaries, top written paths, top network processes, and final JSON summary
- reduced dropped-file triage noise by focusing on suspicious and user-writable locations
- reduced false findings caused by the tool’s own snapshotting activity
- better GUI handling of samples that exit with nonzero return codes

### Fixed

- Procmon launch hang caused by blocking startup behavior
- GUI worker-thread issue that prevented backend execution
- scheduled-task snapshot reliability issues from PowerShell JSON handling
- excessive dropped-file overcounting during benign runs
- self-generated false persistence and LOLBin findings

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

### 10. Paths fail in Linux

Use Linux-style paths in the GUI, not Windows paths.

## Safety Notes

- dynamic analysis should only be performed inside an isolated, revertible Windows VM or other controlled sandbox
- do not run unknown samples on a personal daily-use host
- Procmon-backed execution and persistence snapshotting can generate significant host noise on non-isolated systems
- legitimate software can still contain powerful APIs, installer behaviors, or autorun-related logic; scoring and findings should always be reviewed in context

## Notes

- API analysis currently applies to Windows PE executables and DLLs through import/API-chain analysis
- dynamic analysis in v5 is intended as a practical triage layer, not a full sandbox replacement
- future work may include tighter Procmon filtering, cleaner VM-first tuning, installer-monitor expansion, and broader behavior correlation

## License

See `LICENSE`.
