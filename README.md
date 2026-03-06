# Static Software / Malware Analysis — Static Triage Pipeline

[![License](https://img.shields.io/github/license/aring87/Static-Software-Malware-Analysis)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20WSL%20%7C%20Windows-orange)
![Status](https://img.shields.io/badge/status-active-success)

A static triage pipeline for Windows executables and installers (EXE, DLL, MSI, CAB, ZIP, 7z, and Inno Setup) that produces SOC-style reports and structured case artifacts for investigation, documentation, and training.

---

## ⚠️ Safety / Isolation Required

**Do not run unknown or untrusted malware on your personal computer or on a production network.**

Use an **isolated analysis environment**:
- A dedicated **Windows or Linux VM** (VirtualBox, VMware, Hyper-V), or **WSL Ubuntu** on an analysis-only host
- No shared credentials, no sensitive files, and no access to corporate networks
- VM snapshots so you can roll back after testing

This project also expects a **project-local Python virtual environment (`.venv`)** so dependencies stay scoped to the repository and do not pollute system Python.

---

## Table of Contents

- [Quickstart](#quickstart)
- [Python Version Support](#python-version-support)
- [Environment Variables](#environment-variables)
- [What It Does](#what-it-does)
- [Repo Layout](#repo-layout)
- [Install on Ubuntu or WSL Ubuntu](#install-on-ubuntu-or-wsl-ubuntu)
- [Install on Windows](#install-on-windows)
  - [Windows — PowerShell (Recommended: No Activation)](#windows--powershell-recommended-no-activation)
  - [Windows — PowerShell (Activation)](#windows--powershell-activation)
  - [Windows — CMD (Activation)](#windows--cmd-activation)
- [capa Setup](#capa-setup)
  - [Install capa CLI](#install-capa-cli)
  - [Install capa Rules](#install-capa-rules)
  - [Install capa Signatures](#install-capa-signatures)
  - [Bootstrap Scripts](#bootstrap-scripts)
- [Running the Pipeline](#running-the-pipeline)
  - [CLI](#cli)
  - [GUI](#gui)
  - [Build a Windows GUI EXE](#build-a-windows-gui-exe)
- [Outputs](#outputs)
- [Windows Notes](#windows-notes)
- [Screenshots](#screenshots)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Quickstart

### Recommended platform
- **Best / most reliable:** Ubuntu or WSL Ubuntu
- **Windows-native:** supported on a best-effort basis; most workflows work, but Unix-oriented tooling is more finicky

### Sanity checks
After setup, these commands should work.

**Windows**
```powershell
.\.venv\Scripts\python.exe -V
.\.venv\Scripts\python.exe -m pip --version
```

**Ubuntu / WSL**
```bash
python3 -V
pip --version
```

---

## Python Version Support

This project is tested and most reliable on:
- **Python 3.11–3.12**

**Python 3.13 is not recommended yet.** Some upstream security tooling dependencies, and some Windows packaging dependencies, may not publish compatible wheels yet.

---

## Environment Variables

These optional environment variables are supported and are especially useful for GUI and EXE workflows:

- `CASE_ROOT_DIR` — where `cases/<case>` output is written
- `CAPA_RULES_DIR` — capa rules folder; may point to either `...\capa-rules` or `...\capa-rules\rules`
- `CAPA_SIGS_DIR` — capa signatures folder, for example `...\tools\capa\sigs`
- `TOOLS_DIR` — override the default tools directory
- `LOGS_DIR` — override the default logs directory

Example:

```powershell
$env:CASE_ROOT_DIR="D:\Projects\static_triage_project\analysis\cases"
$env:CAPA_RULES_DIR="D:\Projects\static_triage_project\analysis\tools\capa-rules"
$env:CAPA_SIGS_DIR="D:\Projects\static_triage_project\analysis\tools\capa\sigs"
```

---

## What It Does

Given a Windows executable or installer, the pipeline creates a case folder and generates:

- Hashes: **MD5, SHA1, SHA256**
- File type identification (`file.txt`)
- Strings extraction (`strings.txt`) with optional **lite mode**
- **capa** capability analysis (`capa.json`, `capa.txt`)
- PE metadata (`pe_metadata.json`) and LIEF metadata (`lief_metadata.json`)
- IOC extraction (`iocs.json`, `iocs.csv`)
- Reports: `report.md`, `report.html`, and `report.pdf` (WeasyPrint)

### Installer payload extraction and subfile triage
- Extracts embedded payloads into `cases/<case>/extracted/`
- Supports recursive extraction for ZIP, 7z, MSI, and CAB files
- Supports **Inno Setup** installers via `innoextract`
- Supports optional subfile triage into `cases/<case>/subfiles/<nn>_<filename>/`

---

## Repo Layout

- `static_triage_engine/` — engine, steps, scoring, and reporting
- `scripts/` — CLI and GUI entry points
- `tools/` — tool assets such as capa signatures and capa rules
- `docs/` — documentation assets and screenshots
- `cases/` — generated output (ignored)
- `samples/` — do not commit samples (ignored)
- `logs/` — runtime logs (ignored)
- `.venv/` — project-local virtual environment (ignored)

---

## Install on Ubuntu or WSL Ubuntu

### System dependencies
```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip \
  p7zip-full cabextract osslsigncode file binutils \
  libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libgdk-pixbuf-2.0-0 \
  libcairo2 libffi-dev
```

### Create and use a virtual environment
```bash
cd /path/to/Static-Software-Malware-Analysis
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Install on Windows

### Install Python 3.12
If you do not already have Python 3.12 installed, `winget` is the simplest option:

```powershell
winget install -e --id Python.Python.3.12
```

Then open a new terminal and verify:

```powershell
py -3.12 -V
```

---

### Windows — PowerShell (Recommended: No Activation)

PowerShell often blocks `Activate.ps1` because of execution policy. The simplest path is to **not activate the venv** and instead call the venv Python directly.

```powershell
# Create the venv (first time only)
py -3.12 -m venv .venv

# Install dependencies
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the CLI:

```powershell
.\.venv\Scripts\python.exe scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

> Note: `source .venv/bin/activate` is Linux / WSL syntax and will not work in Windows PowerShell.

---

### Windows — PowerShell (Activation)

If you prefer activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

### Windows — CMD (Activation)

```bat
py -3.12 -m venv .venv
.\.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the CLI:

```bat
python scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

Delete the venv if needed:

**PowerShell**
```powershell
Remove-Item -Recurse -Force .\.venv
```

**CMD**
```bat
rmdir /s /q .venv
```

---

## capa Setup

### Install capa CLI

**Important:** `pip install capa` may install an unrelated package. Install the official FLARE capa package instead.

**Ubuntu / WSL**
```bash
pip install flare-capa
capa --version
```

**Windows**
```powershell
.\.venv\Scripts\python.exe -m pip install flare-capa
.\.venv\Scripts\capa.exe --version
```

---

### Install capa Rules

Install rules into:

```text
tools\capa-rules\rules\
```

Verify:

```powershell
Test-Path .\tools\capa-rules\rules
(dir .\tools\capa-rules\rules -Recurse -Filter *.yml).Count
```

---

### Install capa Signatures

If capa reports missing signatures, use the repository signatures path explicitly:

```powershell
.\.venv\Scripts\capa.exe -r .\tools\capa-rules\rules -s .\tools\capa\sigs D:\path\to\sample.exe
```

Verify:

```powershell
dir .\tools\capa\sigs
```

---

### Bootstrap Scripts

**Windows (PowerShell)**
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap_capa_rules.ps1
```

**Linux / WSL**
```bash
bash scripts/bootstrap_capa_rules.sh
```

---

## Running the Pipeline

### CLI

**Ubuntu / WSL**
```bash
source .venv/bin/activate
python3 scripts/static_triage.py /path/to/sample.exe --case MyCase --no-progress
```

**Windows PowerShell**
```powershell
.\.venv\Scripts\python.exe scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

### GUI

The current Windows GUI work is centered on:
- `scripts/static_triage_gui_v10.py`

Key GUI improvements include:
- Progress bars driven by `analysis.log` parsing (`STEP_START`, `STEP_DONE`, `STEP_FAIL`, `CASE_DONE`)
- Case output folder support through `CASE_ROOT_DIR`
- capa rules and signatures folder selectors
- Better handling for timestamped log lines
- Better report and finalize state handling
- Windows-safe UTF-8 output handling
- Clearer Windows labeling for tools that are more reliable on Linux

Run the GUI on Windows:

```powershell
cd D:\Projects\static_triage_project\analysis
.\.venv\Scripts\python.exe .\scripts\static_triage_gui_v10.py
```

Run the GUI on Ubuntu / WSL:

```bash
source .venv/bin/activate
python3 -m scripts.static_triage_gui
```

---

## Build a Windows GUI EXE

### Recommended build mode: `--onedir`
`--onedir` is recommended because bundled folders such as `tools\...` remain easy to inspect and troubleshoot next to the executable.

1. Install PyInstaller into the project venv:
```powershell
cd D:\Projects\static_triage_project\analysis
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install pyinstaller
.\.venv\Scripts\python.exe -m PyInstaller --version
```

2. Clean previous build artifacts:
```powershell
Remove-Item -Recurse -Force .\build, .\dist -ErrorAction SilentlyContinue
```

3. Build the GUI:
```powershell
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --onedir --windowed `
  --add-data "tools\capa-rules\rules;tools\capa-rules\rules" `
  --add-data "tools\capa\sigs;tools\capa\sigs" `
  scripts\static_triage_gui_v10.py
```

4. Run the EXE from `dist\<app>\`.

> `--onefile` extracts to a temporary folder at runtime, which makes path troubleshooting harder. Use `--onedir` unless you have a strong reason not to.

---

## Outputs

Each run creates a case folder similar to this:

```text
cases/<case_name>/
  summary.json
  runlog.json
  analysis.log
  signing.json
  file.txt
  strings.txt
  capa.json
  capa.txt
  pe_metadata.json
  lief_metadata.json
  iocs.json
  iocs.csv
  report.md
  report.html
  report.pdf
  extracted/                      (if extraction is enabled)
  extracted_manifest.json
  subfiles/<nn>_<filename>/       (if subfile triage is enabled)
```

---

## Windows Notes

Windows support is available, but some tooling is inherently more reliable on Linux or WSL.

### Expected Windows behavior
- `LIEF Analysis` works when **LIEF is installed into the same Python environment the GUI is using**
- `7z.exe` may be required for extraction workflows and must be reachable in `PATH`
- `Report Generation` may produce `report.md` and `report.html` even when `report.pdf` is unavailable
- `File Type` and `Strings` are labeled as **Linux tool / optional on Windows** because those tools are Unix-oriented and can be inconsistent on native Windows

### Practical guidance
- **Best reliability:** Ubuntu or WSL Ubuntu
- **Best Windows experience:** use the project `.venv`, install required Python packages into that venv, and treat Linux-oriented tools as optional

### Report generation on Windows
If `report.pdf` is `None` on Windows, open `report.html` and use **Print to PDF**.

---

## Screenshots

![Main view](docs/screenshots/main-view.png)
![Case folder](docs/screenshots/case-folder.png)
![HTML view](docs/screenshots/html-view.png)
![HTML view 2](docs/screenshots/html-2.png)
![PDF view 2](docs/screenshots/pdf-2.png)

---

## Troubleshooting

### PowerShell: scripts are disabled
Use the **No Activation** method, or allow local scripts for your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### The GUI uses a different Python than the one you tested manually
This is common on Windows. If the GUI launches with `.venv\Scripts\python.exe`, install packages into that venv, not into system Python.

Example:

```powershell
& "D:\Projects\static_triage_project\analysis\.venv\Scripts\python.exe" -m pip install lief
& "D:\Projects\static_triage_project\analysis\.venv\Scripts\python.exe" -c "import lief; print(lief.__version__)"
```

### `lief_meta` fails with `No module named 'lief'`
Install LIEF into the same Python environment that runs the pipeline:

```powershell
.\.venv\Scripts\python.exe -m pip install lief
.\.venv\Scripts\python.exe -c "import lief; print(lief.__version__)"
```

### `extract` fails on Windows because 7-Zip is not found
Confirm that `7z.exe` exists and is available in `PATH`.

Typical install path:

```text
C:\Program Files\7-Zip\7z.exe
```

Temporary session test:

```powershell
$env:Path += ";C:\Program Files\7-Zip"
where.exe 7z
```

Persist for the current user:

```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\7-Zip", "User")
```

Then open a new PowerShell window and verify:

```powershell
where.exe 7z
```

### `File Type` or `Strings` show `Not Available` on Windows
That is expected in many native Windows setups. These steps rely on Unix-oriented tools that are more dependable on Ubuntu, WSL, or other Linux environments.

Treat these as optional on Windows unless you intentionally install compatible equivalents.

### `report.pdf` is missing on Windows
Open `report.html` and use **Print to PDF**.

### `capa` rules directory not found
Common causes:
- You pointed at `...\tools\capa-rules` instead of `...\tools\capa-rules\rules`
- You launched the GUI EXE from a folder that does not contain bundled rules

Verify:

```powershell
Test-Path .\tools\capa-rules\rules
(dir .\tools\capa-rules\rules -Recurse -Filter *.yml).Count
```

### Default signature path does not exist
Verify signatures:

```powershell
dir .\tools\capa\sigs
```

### GUI output stops updating or raises Unicode decode issues
Some tool output contains bytes that Windows code pages do not decode cleanly.

Use UTF-8-safe subprocess handling:
- `encoding="utf-8"`
- `errors="replace"`
- `PYTHONIOENCODING=utf-8`

### Cases are written to the wrong folder
Use either:
- the GUI case output folder selector, or
- `CASE_ROOT_DIR`

Quick test:

```powershell
$env:CASE_ROOT_DIR="D:\Projects\static_triage_project\analysis\cases"
.\.venv\Scripts\python.exe -c "from static_triage_engine.config import TriageConfig; c=TriageConfig(); print(c.cases_dir)"
```

### Dependency conflicts inside the venv
Use a fresh `.venv` for this project. Avoid reusing a virtual environment that already contains unrelated reverse engineering tools.

### Git push rejected with `fetch first`
Your local branch is behind the remote branch:

```powershell
git pull --rebase origin main
# resolve conflicts if prompted
git add <files>
git rebase --continue
git push
```

---

## Contributing

Pull requests are welcome. Please do not commit:
- malware samples
- generated `cases/` output
- large binaries

---

## License

See `LICENSE`.
