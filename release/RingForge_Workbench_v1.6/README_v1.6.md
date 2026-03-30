# RingForge Workbench

RingForge Workbench is a Windows-focused software analysis platform designed to help analysts perform structured triage across multiple workflows from a single interface. It combines static triage, dynamic behavior review, API analysis, specification review, and browser extension analysis into one toolset with a consistent analyst-oriented workflow.

Version 1.6 introduces a new startup experience with a branded splash screen and launcher, along with the first release of Browser Extension Analysis for Chromium-style browser extensions.

---

## Core Capabilities

### Static Analysis
RingForge Workbench includes a full static triage workflow for executables, libraries, installers, archives, and extracted content. Static analysis supports:
- File hashing
- PE and metadata review
- LIEF-based enrichment
- Strings analysis
- Capa analysis
- IOC extraction
- Risk scoring
- Report generation

### Dynamic Analysis
Dynamic Analysis supports runtime behavior review and evidence collection for Windows samples. Depending on configuration and environment, this can include:
- Process and behavior capture
- Interesting event filtering
- Dropped-file review
- Persistence snapshot and diff workflows
- Dynamic findings review

### API Analysis
API Analysis supports manual analyst review of application and service APIs, including:
- Manual API request testing
- Response inspection
- Structured analyst workflow through the dedicated API window

### Spec Analysis
Spec Analysis supports OpenAPI and Swagger-style specification review, including:
- Endpoint inventory
- Risk-oriented spec review
- Identification of potentially risky endpoints and patterns

### Browser Extension Analysis
Browser Extension Analysis is new in v1.6 and supports static triage of browser extensions, including:
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
- Manifest JSON viewing
- Quick-save JSON export
- Quick-save HTML export
- Report folder support

---

## New in v1.6
- Added a RingForge splash screen
- Added a launcher/home screen for workflow selection
- Added Browser Extension Analysis
- Added JSON and HTML export support for browser extension reports
- Styled browser extension reports to match the rest of RingForge reporting
- Improved the startup experience and navigation flow across the application

---

## Workflow Launcher
RingForge Workbench now launches into a startup screen that provides direct access to:
- Static Analysis
- Dynamic Analysis
- API Analysis
- Spec Analysis
- Browser Extension Analysis

This makes the tool easier to navigate and provides a cleaner entry point for analysts.

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
- Background/service worker usage
- Content scripts
- Web-accessible resources
- Externally connectable settings
- Common code patterns such as:
  - eval
  - new Function
  - XMLHttpRequest
  - fetch
  - document.cookie
  - chrome.cookies
  - chrome.tabs
  - chrome.scripting
  - chrome.webRequest
  - remote URLs

### Export support
Browser extension results can be saved quickly as:
- JSON
- HTML

The HTML export uses the same RingForge visual style as the main reporting workflow.

---

## Typical Use Cases
RingForge Workbench can be used for:
- Software triage
- Suspicious executable review
- Installer and archive analysis
- Browser extension review
- API testing
- Spec review
- Structured analyst documentation and reporting

---

## Project Structure
Common project areas include:
- `assets/`
- `cases/`
- `dynamic_analysis/`
- `gui/`
- `scripts/`
- `static_triage_engine/`
- `tools/`
- `release/`

---

## Startup and Launch
The primary startup entry point for the v1.6 launcher flow is:

```text
scripts/static_triage_gui.py
```

This entry point launches the splash screen and workflow launcher. Static Analysis can then be opened from the launcher.

---

## Reporting
RingForge Workbench supports report generation across its analysis workflows. Browser Extension Analysis now includes:
- quick-save JSON reports
- quick-save HTML reports
- report folder support

The HTML report theme matches the broader RingForge report design language.

---

## Platform Notes
- Windows-focused analyst workflow
- Tkinter-based GUI
- Supports local analyst triage and review workflows
- Browser Extension Analysis in v1.6 is focused on static review, not dynamic browser execution

---

## Version
Current release target: **v1.6**
