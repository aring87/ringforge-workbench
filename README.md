# RingForge Workbench

[![Release](https://img.shields.io/badge/release-v1.6-blue)](https://github.com/aring87/ringforge-workbench/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://github.com/aring87/ringforge-workbench)
[![Python](https://img.shields.io/badge/python-3.12-yellow)](https://www.python.org/)
[![Analysis](https://img.shields.io/badge/analysis-static%20%7C%20dynamic%20%7C%20spec%20%7C%20browser%20extension-orange)](https://github.com/aring87/ringforge-workbench)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)](https://github.com/aring87/ringforge-workbench)

**Static insight. Dynamic visibility. Structured review.**

RingForge Workbench is a Windows-focused software triage platform built to support structured static analysis, dynamic behavior review, API analysis, API specification review, and browser extension analysis from a single interface. It is designed for analysts who want a cleaner workflow, better organized outputs, and consistent reporting across multiple software assessment paths.

Version **1.6** introduces a new startup experience with a branded splash screen and launcher, along with the first release of **Browser Extension Analysis** for Chrome, Edge, and Chromium-style extensions.

---

## Current Release

**Version:** v1.6

---

## Overview

RingForge Workbench helps analysts triage Windows software samples such as EXEs, DLLs, installers, launchers, and related package files. It combines metadata extraction, strings analysis, capa behavior analysis, IOC extraction, signing validation, VirusTotal reputation, executable API import analysis, controlled dynamic runtime behavior collection, API specification analysis, and browser extension analysis into one broader assessment workflow.

The platform creates case-based output and produces structured artifacts such as JSON analysis files, IOC exports, Markdown and HTML reports, PDF reports when supported, Procmon-derived runtime artifacts, persistence diffs, dynamic findings summaries, API spec inventory reports, and browser extension analysis reports.

---

## What's New - v1.7 progress (4/2/2026)

RingForge Workbench has been refactored away from the older **combined score on every window** model and moved to a cleaner, more modular **per-test scoring** design.

Each analysis module now focuses on its own results, its own report output, and its own scoring pipeline. The unified reporting flow has also been updated so it only shows scores for modules that were actually run.

---

## Scoring Model Refactor

### Per-Test Scoring Replaces Combined Window Scoring

RingForge now uses a simpler module-driven approach:

- **Static Analysis** shows only the static test’s own results
- **Dynamic Analysis** shows only the dynamic test’s own results
- **Spec Analysis** remains independent and stores its own output
- **Manual API Tester** remains request/response focused and does not force a security-style score
- **Unified Report** shows only the module scores that actually exist

This replaces the older model where multiple windows tried to share or refresh a combined score state.

---

## Static Analysis Improvements

The Static Analysis window was cleaned up to follow the new per-test model.

### Updated Results Panel
The static Results panel now shows only:

- **Score**
- **Verdict**
- **Confidence**
- **VirusTotal**

Older combined/subscore display logic was removed.

### Static Score Loading Fix
A score-loading bug was fixed after confirming that static result JSON stores the value under:

- `risk_score`

instead of:

- `score`

The static result controller was updated to read the correct field, which restored score visibility on the main static screen.

### Static Summary Save Fix
Static summary saving was also rewritten so static runs now save only their own:

- score
- verdict
- confidence

This removed leftover dependencies on deleted combined-score fields.

---

## Dynamic Analysis Improvements

Dynamic Analysis now has its own complete score pipeline.

### Dynamic Score Support
Dynamic scoring was added at the source so dynamic summary output now includes:

- `score`
- `severity`
- `verdict`

These values are now reflected in:

- the dynamic summary JSON
- the dynamic HTML report
- the GUI Findings Summary section

### Dynamic HTML Freshness Fix
The dynamic HTML report is now regenerated from current data when opened, rather than only being reused if a file already exists. This prevents stale report output from conflicting with current GUI results.

### Dynamic Window Cleanup
The Dynamic Analysis window was also cleaned up for a more consistent workflow:

- removed redundant action buttons from the Dynamic Settings area
- fixed duplicated status label behavior
- consolidated report actions into the Findings Summary area
- added score display support directly in Findings Summary

---

## Spec Analysis Cleanup

The Spec Analysis module was decoupled from the old combined-score refresh behavior.

It now behaves as its own independent analysis window that:

- analyzes spec files
- saves its own JSON results
- generates its own HTML reports
- stores its own latest spec result

This keeps Spec Analysis aligned with the new modular architecture.

---

## Manual API Tester

The Manual API Tester remains a separate request/response-focused module.

It was kept intentionally scoreless for now, since the most meaningful output for this workflow is:

- HTTP status
- response time
- content type
- response size

This keeps the tool practical without forcing it into the same security scoring model as static or dynamic analysis.

---

## Unified Report Changes

The Unified Report was updated to reflect the new per-module architecture.

### New Unified Report Behavior
Instead of centering around combined-score language, the unified report now shows only the module results that actually exist.

It is now designed to present:

- **Static Score**
- **Dynamic Score**
- **Spec Score**

only when those modules were actually run.

### Improved Module Detection
Detection logic was tightened so stale artifacts do not create false positives, especially for manual API activity.

Manual API output is now represented more clearly as:

- **Manual API Tester**

rather than being mixed into older combined-report assumptions.

---

## Launcher and Dynamic Analysis Integration

Launcher-to-Dynamic Analysis behavior was improved so saved-test context can now flow correctly into the Dynamic Analysis window.

### Context Passing Improvements
The launcher now supports passing saved test context such as:

- test name
- analysis type
- sample path
- case directory

This allows Dynamic Analysis to open with better awareness of the selected saved test.

### “Use Main Sample” Fix
The **Use Main Sample** action in Dynamic Analysis was updated to fall back to launcher-selected saved test context when live in-memory sample values are not available.

This makes the workflow more reliable when launching modules from the launcher instead of from an already-open static analysis session.

---

## Static Window Workflow Update

The Static Analysis window layout was adjusted for a cleaner flow.

### Artifact Action Order
The **Open Dynamic Analysis** button was moved out of the main static action row and into the Artifacts section.

The order is now:

1. **Open Case**
2. **Open Static Report**
3. **Open Dynamic Analysis**

This makes artifact-related actions feel more consistent and reduces clutter in the main run area.

---

## UI Cleanup Summary

Additional interface cleanup included:

- removal of redundant dynamic window buttons
- elimination of duplicate status labels
- cleaner Findings Summary layout
- better separation between run controls and report actions
- improved consistency between launcher behavior and module windows

---

## Files Updated

Key files touched during this refactor included:

- `gui/main_sections.py`
- `gui/main_app.py`
- `gui/result_controller.py`
- `gui/static_analysis_controller.py`
- `gui/dynamic_window.py`
- `dynamic_analysis/orchestrator.py`
- `dynamic_analysis/html_report.py`
- `gui/spec_window.py`
- `gui/api_window.py`
- `gui/unified_report_window.py`
- `gui/startup_app.py`
- `gui/launcher.py`

---

## Current Direction

RingForge Workbench is now moving toward a cleaner module-based architecture where:

- each module owns its own results
- each module manages its own score and report output
- the unified report summarizes what was actually run
- UI workflows are simpler and less coupled than before

This lays the groundwork for future improvements without the older combined-score dependencies across unrelated windows.

## What’s New in v1.6

RingForge Workbench v1.6 is a workflow and usability release that turns the modular GUI work from v1.5 into a more polished analyst-facing experience. This version improves how users enter the platform, choose workflows, and review browser extension packages while preserving the existing static triage functionality.

### Highlights
- Added a branded RingForge splash screen
- Added a launcher/home screen for workflow selection
- Added **Browser Extension Analysis**
- Added support for unpacked browser extension folders
- Added support for ZIP-based extension analysis
- Added support for CRX-based extension analysis
- Added manifest parsing and summary review for browser extensions
- Added file inventory and file preview for extension contents
- Added browser extension risk notes, risk scoring, and verdicting
- Added color-coded browser extension verdict display
- Added quick-save JSON export for browser extension reports
- Added quick-save HTML export for browser extension reports
- Added report folder support for browser extension reporting
- Styled browser extension HTML reports to match the broader RingForge reporting theme
- Improved startup and navigation flow across the platform

### v1.6 Changelog

#### Startup / Launcher
- Added splash screen support
- Added a launcher-based startup flow
- Added direct workflow selection for Static, Dynamic, API, Spec, and Browser Extension Analysis
- Preserved the existing static analysis interface while moving it behind the new startup flow

#### Browser Extension Analysis
- Added a dedicated Browser Extension Analysis window
- Added support for unpacked browser extension folders
- Added support for ZIP archives
- Added support for CRX packages
- Added manifest parsing and summary extraction
- Added browser extension file inventory view
- Added browser extension file preview panel
- Added risk notes generation based on manifest and quick source review
- Added risk scoring and verdict mapping
- Added color-coded verdict display
- Added quick-save JSON report export
- Added quick-save HTML report export
- Added report folder support

#### Reporting / UI
- Extended RingForge reporting style into browser extension HTML reports
- Improved layout and usability of the extension analysis workspace
- Improved launcher naming and flow clarity
- Improved extension analysis focus behavior after source selection
- Continued visual consistency with the RingForge dark blue / black / white styling

### Why v1.6 matters

Version 1.6 gives RingForge Workbench a cleaner entry point and a stronger platform identity. Instead of opening directly into one workflow, the application now launches into a branded selector that makes the tool easier to navigate and easier to expand.

This release also adds a meaningful new analysis area with Browser Extension Analysis, extending RingForge Workbench beyond Windows software triage into structured review of browser extension packages, permissions, manifests, and related source content.

---

## Earlier Version Highlights

### v1.5
GUI modularization and maintainability release:
- Separated major GUI windows into dedicated modules
- Moved theme logic into `gui/styles.py`
- Improved maintainability and reduced risk for future GUI enhancements
- Established the structural foundation for the launcher and additional workflows

### v1.4
Analysis quality and false-positive reduction release:
- Dynamic scoring tuned to reduce environmental and benign-runtime noise
- Signature verification handling improved for valid signed software
- Capa timeout and large-file skip support added for heavy binaries
- YARA integration and report visibility improved
- API Spec Analysis hardened with richer endpoint risk context

---

## Core Workflows

### Static Analysis
RingForge Workbench includes a full static triage workflow for Windows executables and related software packages. Static analysis supports:
- File hashing
- PE and metadata review
- LIEF-based enrichment
- Strings analysis
- capa analysis
- IOC extraction
- Risk scoring
- Markdown / HTML / PDF report generation

### Dynamic Analysis
Dynamic Analysis supports runtime behavior review and evidence collection for Windows samples. Depending on configuration and environment, this can include:
- Process and behavior capture
- Interesting event filtering
- Dropped-file review
- Persistence snapshot and diff workflows
- Dynamic findings review
- HTML and PDF reporting

### API Analysis
API Analysis supports manual analyst review of application and service APIs, including:
- Manual API request testing
- Response inspection
- Structured analyst workflow through the dedicated API window

### API Spec Analysis
Spec Analysis supports OpenAPI and Swagger-style specification review, including:
- Endpoint inventory
- Risk-oriented spec review
- Identification of potentially risky endpoints and patterns
- HTML inventory reporting

### Browser Extension Analysis
Browser Extension Analysis is new in v1.6 and supports static review of browser extensions, including:
- Unpacked browser extension folders
- ZIP extension packages
- CRX packages

Browser Extension Analysis includes:
- Manifest parsing
- File inventory
- File preview
- Risk notes
- Risk score
- Risk verdict
- Color-coded verdict display
- Manifest JSON viewing
- Quick-save JSON export
- Quick-save HTML export
- Report folder support

---

## Workflow Launcher

RingForge Workbench now opens into a launcher that provides direct access to:
- Static Analysis
- Dynamic Analysis
- API Analysis
- Spec Analysis
- Browser Extension Analysis

This gives the platform a cleaner entry point and makes it easier to expand additional workflows over time.

---

## Browser Extension Analysis Overview

The Browser Extension Analysis module is designed for Chrome, Edge, and Chromium-style extensions.

### Supported sources
- Unpacked folder
- ZIP archive
- CRX package

### Summary information shown
- Name
- Version
- Description
- Manifest Version
- Permissions
- Host Permissions
- Background / Service Worker
- Content Scripts
- Web Resources
- Externally Connectable
- Update URL
- Commands
- CSP
- Risk Score
- Risk Verdict
- Files Found

### Risk notes and detection ideas
The module currently performs quick static checks against:
- Manifest permissions
- Host permissions
- Background / service worker usage
- Content scripts
- Web-accessible resources
- Externally connectable settings
- Common code patterns such as:
  - `eval`
  - `new Function`
  - `XMLHttpRequest`
  - `fetch`
  - `document.cookie`
  - `chrome.cookies`
  - `chrome.tabs`
  - `chrome.scripting`
  - `chrome.webRequest`
  - remote URLs

### Export support
Browser extension results can be quick-saved as:
- JSON
- HTML

The HTML export uses the same RingForge visual style as the main reporting workflow.

---

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

### Browser Extension report outputs

A Browser Extension Analysis run can produce a report folder like:

```text
ringforge_extension_reports/
  <extension_name>_extension_analysis.json
  <extension_name>_extension_analysis.html
```

---

## Repo Layout

```text
ringforge-workbench/
  assets/
  docs/
  scripts/
  static_triage_engine/
  dynamic_analysis/
  gui/
  tools/
    procmon-configs/
  cases/                 # generated locally, usually gitignored
  logs/                  # generated locally, usually gitignored
  release/
  .gitignore
  LICENSE
  README.md
  requirements.txt
```

---

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
- `pillow` (for image-backed branding and splash assets)
- any packages listed in `requirements.txt`

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

---

## Windows Setup Example

```powershell
cd C:\RingForge_Analyzer\Static-Software-Malware-Analysis
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

---

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

---

## Running the GUI

### Windows

```powershell
cd C:\RingForge_Analyzer\Static-Software-Malware-Analysis
.\.venv\Scripts\Activate.ps1
python .\scripts\static_triage_gui.py
```

### Linux

```bash
cd ~/analysis/ringforge-workbench
source .venv/bin/activate
python scripts/static_triage_gui.py
```

---

## Packaging RingForge Workbench v1.6

### Build

Example PyInstaller build:

```powershell
pyinstaller --noconfirm --clean --distpath .\dist --workpath .\build .\RingForgeWorkbench.spec
```

### Release folder

Create the release folder and copy:
- built application folder
- `config.json`
- `README_v1.6.md`
- `LICENSE`
- `requirements.txt`

### Zip

```powershell
Compress-Archive -Path .\release\RingForge_Workbench_v1.6\* -DestinationPath .\release\RingForge_Workbench_v1.6.zip -Force
```

---

## Safety Notes

- Dynamic analysis should only be performed inside an isolated, revertible Windows VM or other controlled sandbox.
- Do not run unknown samples on a personal daily-use host.
- Procmon-backed execution and persistence snapshotting can generate significant host noise on non-isolated systems.
- Legitimate software can still contain powerful APIs, installer behaviors, or autorun-related logic; scoring and findings should always be reviewed in context.
- Browser extensions can request powerful permissions and still be legitimate; extension findings should always be reviewed in analyst context.
- API spec analysis can highlight risky routes, methods, auth patterns, and follow-up test ideas, but findings still require analyst review in context.

---

## Notes

- API analysis currently applies to Windows PE executables and DLLs through import/API-chain analysis.
- API Spec Analysis currently supports OpenAPI and Swagger definition files in JSON or YAML form.
- Browser Extension Analysis in v1.6 is focused on static review, not dynamic browser execution.
- Dynamic analysis in RingForge Workbench is intended as a practical triage layer, not a full sandbox replacement.

---

## License

See `LICENSE`.
