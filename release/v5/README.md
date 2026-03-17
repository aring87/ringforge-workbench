# Static Software / Malware Analysis — Static Triage Pipeline

A static triage pipeline for Windows executables and installers that produces structured case artifacts, risk scoring, IOC extraction, signing verification results, API behavior analysis, and analyst-friendly reports.

## Overview

This project is designed to help analysts quickly triage Windows software samples such as EXE, DLL, installer, and launcher files. It combines metadata extraction, strings analysis, capa behavior analysis, IOC extraction, signing validation, VirusTotal reputation, and executable API import analysis into a single workflow.

The pipeline creates a case folder for each run and produces structured outputs such as JSON artifacts, CSV IOC files, Markdown and HTML reports, and PDF reports when supported.

## What’s New in v4

Version 4 adds stronger signing validation, executable API analysis, API-chain-aware scoring, and improved false-positive handling for legitimate signed installer and launcher software.

### Highlights

- corrected Authenticode verification parsing from `osslsigncode`
- signing cache now reparses cached raw output so parser improvements apply to older samples
- executable API import analysis for PE files
- API behavior chain detection
- `api_analysis.json` output artifact
- API Analysis section in Markdown and HTML reports
- light API-chain contribution to scoring
- benign-context dampening for trusted signed clean installers and updaters
- improved scoring stability for legitimate software from vendor sources

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

### Reporting

- Markdown report
- HTML report
- PDF report when environment supports it
- structured summary and runlog outputs

### Extraction support

- embedded payload extraction
- recursive extraction support
- extracted payload manifest
- optional extracted PE subfile triage

## API Analysis

v4 adds executable API import analysis for Windows PE files.

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

## Typical Workflow

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

## Outputs

A typical case folder may contain:

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

## Recommended Release Folder Layout

```text
Static_Software_Malware_Analysis_v4/
  Static_Software_Malware_Analysis_v4.exe
  scripts/
    static_triage.py
    static_triage_engine/
  tools/
    capa-rules/
    capa/
      sigs/
  README.md
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

## Running the CLI

Example help command:

```bash
python scripts/static_triage.py --help
```

Example analysis run:

```bash
python scripts/static_triage.py "/path/to/sample.exe"
```

## Packaging Version 4

### Build

Example PyInstaller build:

```bash
pyinstaller --onedir --windowed --name Static_Software_Malware_Analysis_v4 scripts/static_triage_gui_v10.py
```

### Release folder

Create the release folder and copy:

- built executable
- `static_triage_engine`
- `scripts`
- `tools/capa-rules`
- `tools/capa/sigs`
- `README.md`
- `LICENSE`
- `requirements.txt` if needed

### Zip

```bash
cd release
zip -r Static_Software_Malware_Analysis_v4.zip Static_Software_Malware_Analysis_v4
```

## Release Notes – v4.0

This release improves the static triage pipeline with stronger signing validation, better false-positive control, executable API analysis, and clearer risk scoring.

### Added

- executable API import analysis
- API behavior chain detection for PE files
- `api_analysis.json` output artifact
- API Analysis section in Markdown and HTML reports
- API-chain scoring support in the risk model

### Improved

- Authenticode parsing now correctly recognizes successful verification states from `osslsigncode`
- signing cache handling now reparses cached raw signing output so improved parsing logic is applied to previously analyzed files
- scoring logic better handles legitimate signed installers and launchers
- VirusTotal-aware dampening and trusted-signature handling reduce false positives more reliably

### Fixed

- cases where valid signed software could still be treated like unsigned or partially trusted samples
- over-scoring of legitimate installer and launcher software
- missing API analysis visibility in reports after feature integration
- stale signing cache results preventing corrected verification logic from being reflected in new runs

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

### 4. capa fails

Check:

- `tools/capa-rules` exists
- `tools/capa/sigs` exists
- capa is installed in the active virtual environment

### 5. LIEF fails

Make sure LIEF is installed in the active virtual environment:

```bash
pip install lief
```

### 6. VirusTotal lookup fails

Common reasons:

- `VT_API_KEY` is not set
- network/DNS failure
- rate limit or API response issue

### 7. Paths fail in Linux

Use Linux-style paths in the GUI, not Windows paths.

## Notes

- API analysis in v4 currently applies to Windows PE executables and DLLs through import/API-chain analysis
- separate API spec and endpoint analysis is planned as a future mode
- legitimate software can still contain powerful APIs; scoring is intentionally conservative and context-aware

## License

See `LICENSE`.
