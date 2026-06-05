# RingForge Workbench

<p align="center">
  <img alt="RingForge Workbench" src="https://img.shields.io/badge/RingForge-Workbench-blue?style=for-the-badge">
  <img alt="Version" src="https://img.shields.io/badge/version-v1.7.2-blue?style=for-the-badge">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-lightgrey?style=for-the-badge">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-green?style=for-the-badge">
  <img alt="Status" src="https://img.shields.io/badge/status-active-success?style=for-the-badge">
</p>

<p align="center">
  <b>Static, dynamic, API, browser extension, and unified software-analysis workbench for security review, malware triage, and analyst reporting.</b>
</p>

---

## Overview

RingForge Workbench is a Windows-focused security analysis workbench designed to help analysts organize and review software, installers, executables, API specifications, browser extensions, and dynamic-analysis results inside a single case-based workflow.

The project is built for practical security review. It focuses on producing useful analyst output instead of raw tool dumps. RingForge organizes results into case folders, generates HTML/JSON/Markdown reports, supports static and dynamic workflows, and now includes polished API Spec Analysis with direct OpenAPI/Swagger URL support.

Version **v1.7.2** focuses on **API Spec Analysis polish** and better Unified Report integration.

---

## Current Release

**RingForge Workbench v1.7.2 — API Spec Analysis Polish**

This release improves the API Spec Analysis workflow, report layout, case-folder organization, and Unified Report integration.

### v1.7.2 Highlights

- Added direct OpenAPI/Swagger URL support for API Spec Analysis.
- Standardized API spec outputs under `cases/<case>/spec_analysis/`.
- Added clean historical run folders under `spec_analysis/runs/`.
- Added latest report files for quick access:
  - `spec_inventory_latest.html`
  - `spec_inventory_latest.json`
  - `api_spec_analysis.json`
- Added compatibility copies for older report readers.
- Improved API spec report wording from **Top Risky Endpoints** to **Notable Endpoints**.
- Improved recommended-test wording to emphasize runtime validation instead of declaring vulnerabilities from the specification alone.
- Added API-specific spec score and verdict support in the Unified Report.
- Added API Analysis and Browser Extension Analysis rows to the Unified Report overview.
- Improved missing-module display with clear labels such as **Not run** and **Not generated**.
- Improved spec-only Unified Report verdicts such as:
  - `Medium API Spec Risk`
  - `High API Spec Risk`
  - `Informational API Spec Review`

---

## Core Features

### Static Analysis

RingForge performs structured static triage against executables, installers, and extracted subfiles.

Static analysis can include:

- PE metadata collection
- LIEF metadata collection
- YARA scanning
- Capa capability analysis
- Authenticode signature review
- Hashing and file identification
- String extraction
- Installer/subfile extraction
- Subfile triage and scoring
- Suspicious capability grouping
- Analyst-friendly static HTML and Markdown reports

The static-analysis workflow is designed to reduce noise and present findings in a way that helps analysts make a risk decision.

---

### Dynamic Analysis

RingForge supports dynamic-analysis case organization and reporting.

Dynamic-analysis workflows can include:

- Dynamic run summaries
- Process execution observations
- Spawned process tracking
- Procmon artifact organization
- Persistence artifact review
- File activity review
- Dynamic findings JSON
- Dynamic HTML report generation
- Unified report integration

Dynamic analysis is organized under the shared case-home structure so static, dynamic, API, spec, and extension findings can be reviewed together.

---

### API Spec Analysis

RingForge Workbench includes an API Spec Analysis module for reviewing OpenAPI and Swagger definitions. The module parses API specifications, builds an endpoint inventory, reviews declared authentication models, identifies notable endpoint patterns, and exports analyst-ready HTML and JSON reports.

#### Supported Inputs

- Local OpenAPI/Swagger files:
  - `.json`
  - `.yaml`
  - `.yml`
- Direct OpenAPI/Swagger URLs:
  - Example: `https://petstore3.swagger.io/api/v3/openapi.json`

When a URL is provided, RingForge downloads the specification into the case folder and analyzes the local copy.

#### API Spec Analysis Capabilities

- Parses OpenAPI/Swagger metadata, version, servers, paths, methods, and schemas
- Builds an endpoint inventory with method, route, summary, auth source, and risk level
- Detects declared authentication schemes such as API key, bearer token, and OAuth2
- Identifies endpoints that do not declare explicit authentication requirements
- Flags destructive or update-oriented methods such as `DELETE`, `PUT`, and `PATCH`
- Highlights file upload endpoints
- Detects sensitive-looking parameters
- Detects PII-like schema fields
- Identifies schema quality issues
- Identifies unresolved references
- Generates recommended manual validation tests
- Produces analyst-ready HTML and JSON reports
- Integrates with the Unified Report

#### Spec Output Layout

API Spec Analysis results are saved under the case folder using the RingForge case layout:

```text
cases/<case_name>/spec_analysis/
  api_spec_analysis.json
  spec_inventory_latest.html
  spec_inventory_latest.json
  downloaded_specs/
  metadata/
    api_spec_analysis.json
  originals/
  runs/
    <timestamp>_<spec_name>/
      api_spec_analysis.json
      spec_inventory.html
      spec_inventory.json
      original_<spec_name>.<ext>
```

The latest files remain at the root of `spec_analysis` for quick access and Unified Report integration. Historical runs are preserved under `spec_analysis/runs/` to keep the case folder organized.

#### API Spec Review Language

RingForge treats API specification findings as **review indicators**, not confirmed vulnerabilities.

For example, the tool recommends:

```text
Validate whether authorization is enforced at runtime, even if the spec does not declare auth.
```

This avoids overstating risk from the specification alone.

---

### Manual API Tester

RingForge includes Manual API Tester support for saving request/response review artifacts into the case folder.

Manual API Tester output can include:

- Request method
- URL
- SSL verification setting
- Timeout
- HTTP response status
- Reason phrase
- Content type
- Elapsed time
- Response size
- Saved HTML and JSON artifacts
- Unified Report integration

---

### Browser Extension Analysis

RingForge includes browser extension analysis support for reviewing extension packages and integrating findings into the Unified Report.

Browser Extension Analysis can support:

- Extension metadata review
- File inventory
- Risk scoring
- Extension verdicts
- Generated JSON reports
- Unified Report detection and summary display

Browser Extension Analysis is planned for additional polish in a future release.

---

### Unified Report

RingForge includes a Unified Report window that scans a case folder and detects available module artifacts.

The Unified Report can detect and summarize:

- Static Analysis
- Dynamic Analysis
- Manual API Tester
- API Spec Analysis
- Browser Extension Analysis
- Combined Score

The Unified Report now includes API-specific spec scoring and verdicts. For spec-only cases, the report uses API-appropriate language instead of malware-analysis language.

Example spec-only overview:

```text
Combined Score: Not generated
Static Score: Not run
Dynamic Score: Not run
API Analysis: Not run
Spec Score: 47
Browser Extension Analysis: Not run
Overall Verdict: Medium API Spec Risk
```

---

## Case Folder Layout

RingForge uses a shared case-home layout:

```text
cases/<case_name>/
  case_metadata.json
  combined_score.json
  metadata/
    static_run_summary.json
    combined_score.json

  static_analysis/
    summary.json
    iocs.json
    pe_metadata.json
    lief_metadata.json
    report.html
    report.md
    metadata/
      static_run_summary.json

  dynamic_analysis/
    dynamic_runs/
      <run_id>/
        metadata/
          dynamic_run_summary.json
        procmon/
        persistence/
        files/
        reports/
          dynamic_findings.json
    reports/
      dynamic_report.html

  api_analysis/
    manual_api_latest.json
    manual_api_latest.html

  spec_analysis/
    api_spec_analysis.json
    spec_inventory_latest.html
    spec_inventory_latest.json
    downloaded_specs/
    metadata/
      api_spec_analysis.json
    originals/
    runs/

  extension_analysis/
    extension_analysis.json
    reports/

  unified_report/
    unified_report.json
    unified_report.html
```

Legacy paths are still supported where possible for compatibility with earlier releases.

---

## External Tools

RingForge can integrate with several external security tools, but these tools are not bundled in releases. Users must download and configure them separately.

Common external tools include:

- YARA
- Capa
- Capa rules
- Capa signatures
- LIEF
- 7-Zip
- Sigcheck
- Procmon
- Procmon configuration files
- Any additional dynamic-analysis utilities required by the analyst workflow

### Why External Tools Are Not Bundled

RingForge does not bundle third-party security tools because:

- Tool licenses may restrict redistribution.
- Tool versions change frequently.
- Some tools are large and would bloat releases.
- Analysts may need to use organization-approved versions.
- Keeping tools external makes RingForge easier to audit and maintain.
- It avoids shipping stale or unauthorized binaries inside the project.

---

## Installation

### Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer
- PowerShell
- Git
- Optional external analysis tools depending on the workflow

### Clone the Repository

```powershell
git clone https://github.com/<your-username>/<your-repo>.git
cd Static-Software-Malware-Analysis
```

### Create a Virtual Environment

```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

### Install Dependencies

```powershell
pip install -r requirements.txt
```

---

## Launching RingForge Workbench

From the project root:

```powershell
python .\scripts\static_triage_gui.py
```

---

## API Spec Analysis Quick Test

Use the public Swagger Petstore OpenAPI definition:

```text
https://petstore3.swagger.io/api/v3/openapi.json
```

Steps:

1. Open RingForge Workbench.
2. Open API Spec Analysis.
3. Paste the URL into the API Spec field.
4. Click Analyze Spec.
5. Open the latest HTML report.
6. Open the Unified Report for the same case folder.
7. Confirm the Spec Analysis Summary and Spec Score appear.

Expected outputs:

```text
cases/<case>/spec_analysis/api_spec_analysis.json
cases/<case>/spec_analysis/spec_inventory_latest.html
cases/<case>/spec_analysis/spec_inventory_latest.json
cases/<case>/spec_analysis/runs/<timestamp>_<spec_name>/
```

---

## Git Hygiene

Do not commit generated analysis artifacts unless intentionally adding test samples.

Avoid committing:

```text
cases/
release/
dist/
build/
.venv/
__pycache__/
*.pyc
```

Stage source files directly instead of using `git add .`:

```powershell
git add .\gui\spec_window.py
git add .\gui\unified_report_window.py
git add .\static_triage_engine\api_spec_analysis.py
git add .\README.md
```

---

## Release Notes

### v1.7.2 — API Spec Analysis Polish

- Added direct URL support for OpenAPI/Swagger specifications.
- Improved API Spec Analysis output organization.
- Added clean historical spec run folders.
- Improved Spec Analysis report wording.
- Added API-specific spec score and verdict support.
- Improved Unified Report module overview.
- Added clearer missing-module labels.
- Improved spec-only case reporting.

### v1.7.1 — Release and Documentation Polish

- Updated release documentation.
- Improved README structure.
- Clarified external tool requirements.
- Clarified that releases do not bundle third-party tools.
- Improved packaging guidance.

### v1.7.0 — Static and Dynamic Analysis Polish

- Improved static-analysis reporting.
- Improved dynamic-analysis reporting.
- Improved subfile triage presentation.
- Improved case-folder organization.
- Improved report readability and analyst workflow.

---

## Development Notes

Recommended syntax checks before committing:

```powershell
python -m py_compile .\gui\spec_window.py
python -m py_compile .\gui\unified_report_window.py
python -m py_compile .\static_triage_engine\api_spec_analysis.py
```

Recommended Git flow:

```powershell
git status
git diff --cached --name-only
git commit -m "Polish API spec analysis workflow"
git push
```

Create a version tag:

```powershell
git tag -a v1.7.2 -m "v1.7.2 - API Spec Analysis polish"
git push origin v1.7.2
```

---

## Disclaimer

RingForge Workbench is an analyst-assist tool. Findings should be reviewed and validated by a qualified analyst. API specification findings indicate review areas and possible exposure patterns; they do not prove runtime vulnerabilities without manual validation or authenticated testing.

---

## Status

Current release: **v1.7.2**

Next planned polish area: **Browser Extension Analysis**
