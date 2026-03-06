# Static Software / Malware Analysis — Static Triage Pipeline

[![License](https://img.shields.io/github/license/aring87/Static-Software-Malware-Analysis)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20WSL%20%7C%20Windows-orange)
![Status](https://img.shields.io/badge/status-active-success)

A static triage pipeline for Windows executables and installers that generates structured case artifacts, IOC output, and SOC-style reports for triage, training, and investigation.

---

## Safety / Isolation Required

**Do not run unknown malware on your personal computer or on a production network.**

Use an isolated lab environment:
- A dedicated Windows or Linux VM, or WSL Ubuntu on an analysis-only host
- No shared credentials or sensitive files
- No access to corporate or home production networks
- Snapshots/checkpoints so you can roll back safely

This project is designed for offline static triage, but you should still treat all samples as hostile.

---

## Quick Summary

This project can analyze Windows EXE, DLL, MSI, CAB, ZIP, 7z, and some installer formats and produce:
- MD5 / SHA1 / SHA256 hashes
- PE and LIEF metadata
- capa capability analysis
- extracted IOCs
- extracted payloads and optional subfile triage
- Markdown, HTML, and optionally PDF reports

---

## Recommended Platforms

### Best overall
- **Ubuntu native**
- **WSL Ubuntu**

### Windows native
Supported, but some tool dependencies are less smooth than Linux.

On Windows, the GUI may show:
- **File Type (Linux tool / optional on Windows): Not Available**
- **Strings (Linux tool / optional on Windows): Not Available**

That is expected when the underlying Linux-oriented tools are not present or are not worth forcing into the Windows workflow.

---

## Python Version Support

Recommended:
- **Python 3.11**
- **Python 3.12**

Not recommended right now:
- **Python 3.13**

Reason: some upstream security tooling and packaging dependencies may not have stable wheels yet.

---

## What the Pipeline Produces

For a given sample, the pipeline creates a case folder and can generate:
- `file.txt`
- `strings.txt`
- `pe_metadata.json`
- `lief_metadata.json`
- `capa.json`
- `capa.txt`
- `iocs.json`
- `iocs.csv`
- `summary.json`
- `report.md`
- `report.html`
- `report.pdf` when PDF generation is supported

It can also create:
- `extracted/` for extracted payloads
- `subfiles/` for optional subfile triage
- `analysis.log` for step tracking
- `runlog.json` for execution details

---

## Repo Layout

```text
analysis/
  docs/
  scripts/
  static_triage_engine/
  tools/
  .gitignore
  LICENSE
  README.md
  requirements.txt
  Static_Triage_GUI.spec
  triage_inbox.py
```

Generated or local-use folders are typically ignored:
- `cases/`
- `logs/`
- `.venv/`
- `build/`
- `dist/`

---

## Optional Environment Variables

These are useful for GUI and EXE workflows:

- `CASE_ROOT_DIR` — case output location
- `CAPA_RULES_DIR` — capa rules folder
- `CAPA_SIGS_DIR` — capa signatures folder
- `TOOLS_DIR` — override tools directory
- `LOGS_DIR` — override logs directory

Example PowerShell:

```powershell
$env:CASE_ROOT_DIR="D:\Projects\static_triage_project\analysis\cases"
$env:CAPA_RULES_DIR="D:\Projects\static_triage_project\analysis\tools\capa-rules"
$env:CAPA_SIGS_DIR="D:\Projects\static_triage_project\analysis\tools\capa\sigs"
```

---

## Install on Ubuntu or WSL Ubuntu

### System packages

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip \
  p7zip-full cabextract osslsigncode file binutils \
  libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libgdk-pixbuf-2.0-0 \
  libcairo2 libffi-dev
```

### Create venv and install Python dependencies

```bash
cd /path/to/analysis
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install flare-capa
```

---

## Install on Windows

### Install Python 3.12

```powershell
winget install -e --id Python.Python.3.12
```

Verify:

```powershell
py -3.12 -V
```

### Recommended Windows approach: use the venv Python directly

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install flare-capa
```

If you prefer activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install flare-capa
```

If PowerShell activation is annoying, you can always call the venv Python directly instead.

---

## Windows Tool Notes

### LIEF
If `LIEF Analysis` fails with `No module named 'lief'`, install it into the **same Python environment the GUI is actually using**.

Examples:

```powershell
.\.venv\Scripts\python.exe -m pip install lief
.\.venv\Scripts\python.exe -c "import lief; print(lief.__version__)"
```

Important: installing `lief` into your system Python will not help if the GUI is launching the backend with `.venv\Scripts\python.exe`.

### 7-Zip
Extraction on Windows may require `7z.exe`.

Common install path:

```text
C:\Program Files\7-Zip\7z.exe
```

Temporary PATH test:

```powershell
$env:Path += ";C:\Program Files\7-Zip"
where.exe 7z
```

Permanent user PATH update:

```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\7-Zip", "User")
```

### File Type and Strings on Windows
The GUI may show these steps as **Not Available**.

That is intentional and beginner-friendly.

They are Linux-oriented helper tools and may be skipped on Windows rather than treated as hard failures.

---

## capa Setup

### Install official capa

Use the official FLARE package, not the unrelated `capa` package.

```powershell
.\.venv\Scripts\python.exe -m pip install flare-capa
.\.venv\Scripts\capa.exe --version
```

### Rules folder
Acceptable examples:

```text
D:\Projects\static_triage_project\analysis\tools\capa-rules
D:\Projects\static_triage_project\analysis\tools\capa-rules\rules
```

### Sigs folder
Example:

```text
D:\Projects\static_triage_project\analysis\tools\capa\sigs
```

---

## Running the CLI

### Basic example

```powershell
.\.venv\Scripts\python.exe scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

### With explicit directories

```powershell
$env:CASE_ROOT_DIR="D:\Projects\static_triage_project\analysis\cases"
$env:CAPA_RULES_DIR="D:\Projects\static_triage_project\analysis\tools\capa-rules"
$env:CAPA_SIGS_DIR="D:\Projects\static_triage_project\analysis\tools\capa\sigs"

.\.venv\Scripts\python.exe scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

---

## Running the GUI

### Source mode

```powershell
.\.venv\Scripts\python.exe scripts\static_triage_gui_v10.py
```

### What GUI v10 improves
- better progress parsing for timestamped `analysis.log`
- handles optional Windows-only step results more clearly
- `Report Generation` and `Finalize` complete correctly on success
- supports `CASE_ROOT_DIR`, `CAPA_RULES_DIR`, and `CAPA_SIGS_DIR`
- clearer labels for Linux-oriented tools on Windows

### Expected Windows statuses
Typical successful Windows run:
- `done` for core steps
- `not available` for Linux-tool-dependent optional steps
- overall progress reaches **100%** on success

---

## Building the Windows EXE

### Build command

```powershell
& "D:\Projects\static_triage_project\analysis\.venv\Scripts\python.exe" -m PyInstaller --noconfirm --onefile --windowed --name Static_Triage_GUI_v10 "D:\Projects\static_triage_project\analysis\scripts\static_triage_gui_v10.py"
```

### Important packaging note
The EXE is currently best treated as a **frontend plus release folder**, not a fully self-contained one-file app with every support asset embedded.

Recommended release folder layout:

```text
Static_Triage_GUI_Release/
  Static_Triage_GUI_v10.exe
  scripts/
    static_triage.py
    static_triage_engine/
  tools/
    capa-rules/
    capa/
      sigs/
  README.md
```

This is the most reliable Windows packaging model right now.

---

## Outputs

A typical case folder may contain:

```text
cases/<case>/
  analysis.log
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
  strings.txt
  subfiles/
  summary.json
```

On Windows, `report.pdf` may be `None`. In that case, open `report.html` and use your browser's **Print to PDF** option.

---

## Troubleshooting

### 1. `No module named 'lief'`
Install `lief` into the same Python the GUI or EXE backend uses.

```powershell
.\.venv\Scripts\python.exe -m pip install lief
```

### 2. `where.exe 7z` says not found
7-Zip may be installed but not in PATH.

Check:

```powershell
Test-Path "C:\Program Files\7-Zip\7z.exe"
```

Temporary fix:

```powershell
$env:Path += ";C:\Program Files\7-Zip"
where.exe 7z
```

### 3. `capa rules folder invalid`
The GUI or EXE cannot find the rules folder.

Point it to one of these:

```text
...\tools\capa-rules
...\tools\capa-rules\rules
```

### 4. `Could not find CLI script: ... static_triage.py`
Your EXE release folder is missing backend files.

Make sure the release folder includes:
- `scripts\static_triage.py`
- `scripts\static_triage_engine\`
- `tools\capa-rules\`
- `tools\capa\sigs\`

### 5. `File Type` or `Strings` show `Not Available`
That is expected on many Windows setups.

These steps rely on Linux-oriented tools and are treated as optional on Windows.

### 6. `report.pdf: None`
Expected on some Windows runs.

Use `report.html` and print it to PDF from the browser.

### 7. Progress looks wrong, stale, or mixed between runs
This usually means you are reusing a case folder whose `analysis.log` already contains older runs.

Use a fresh case name for cleaner progress behavior.

### 8. PowerShell activation fails
You can skip activation entirely and call the venv Python directly.

```powershell
.\.venv\Scripts\python.exe scripts\static_triage_gui_v10.py
```

### 9. EXE launches but defaults to bad paths
The EXE may need a full release folder next to it. Do not test it by copying just the EXE alone without the supporting `scripts` and `tools` folders.

---

## Recommended `.gitignore`

A clean repo should ignore build artifacts, runtime output, and local-only configuration.

```gitignore
# Python
__pycache__/
*.pyc
*.pyo

# Virtual environments
.venv/
venv/

# Build artifacts
build/
dist/

# Runtime output
cases/
logs/
config.json

# Release artifacts
*.zip

# Backups
*.bak

# OS/editor junk
Thumbs.db
.DS_Store
```

If you want to keep `Static_Triage_GUI.spec`, do not ignore `*.spec`.

---

## Contributing

Keep commits focused and avoid committing:
- malware samples
- generated case folders
- local config files
- build artifacts
- release ZIPs

Good candidates to commit:
- `scripts/`
- `static_triage_engine/`
- `tools/`
- `docs/`
- `README.md`
- `requirements.txt`
- `LICENSE`
- `Static_Triage_GUI.spec`

---

## License

See [LICENSE](LICENSE).
