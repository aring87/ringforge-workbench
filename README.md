# Static Software / Malware Analysis — Static Triage Pipeline

[![License](https://img.shields.io/github/license/aring87/Static-Software-Malware-Analysis)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20WSL%20%7C%20Windows-orange)
![Status](https://img.shields.io/badge/status-active-success)

A static triage pipeline for Windows executables and installers (EXE/DLL/MSI/CAB/ZIP/7z/Inno Setup) that produces SOC-style reports and structured case artifacts for investigation and training.

---

## ⚠️ Safety / Isolation Required (Read First)

**Do NOT run unknown malware on your personal computer or on a production network.**

Use an **isolated analysis environment**:
- A dedicated **Windows/Linux VM** (VirtualBox/VMware/Hyper‑V) **or** **WSL Ubuntu** on an analysis-only Windows host
- No shared credentials, no sensitive files, and no access to corporate networks
- Use **snapshots** so you can roll back after testing

This project also expects a **Python virtual environment (`.venv`)** so dependencies install locally to the project and don’t pollute your system Python.

---

## Table of Contents

- [Quickstart](#quickstart)
- [Python Version Support](#python-version-support)
- [What It Does](#what-it-does)
- [Repo Layout](#repo-layout)
- [Install Ubuntu or WSL Ubuntu](#install-ubuntu-or-wsl-ubuntu)
- [Install Windows](#install-windows)
  - [Windows — PowerShell (Recommended: No Activation)](#windows--powershell-recommended-no-activation)
  - [Windows — PowerShell (Activation)](#windows--powershell-activation)
  - [Windows — CMD (Activation Works)](#windows--cmd-activation-works)
- [capa Setup](#capa-setup)
  - [Install capa CLI](#install-capa-cli)
  - [Install capa Rules](#install-capa-rules)
  - [Install or Use capa Signatures](#install-or-use-capa-signatures)
  - [Bootstrap Scripts](#bootstrap-scripts)
- [Running](#running)
  - [CLI](#cli)
  - [GUI](#gui)
- [Outputs](#outputs)
- [Screenshots](#screenshots)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Quickstart

### Choose your path
- ✅ **Best/Most reliable:** **Ubuntu** (native) or **WSL Ubuntu**
- ⚠️ **Windows-native:** supported “best effort” (works, but dependency/tooling friction is more common)

### Sanity checks
After setup, these should work:

**Windows**
```powershell
.\.venv\Scripts\python.exe -V
.\.venv\Scripts\python.exe -m pip --version
```

**Ubuntu/WSL**
```bash
python3 -V
pip --version
```

---

## Python Version Support

This project is currently tested and most reliable on:
- **Python 3.11 – 3.12** (recommended)

⚠️ **Python 3.13 is not recommended right now.** Some upstream security tooling dependencies (and Windows build tooling such as PyInstaller-related packages) may not publish compatible wheels for Python 3.13 yet, which can cause `pip install -r requirements.txt` to fail.

---

## What It Does

Given a Windows executable/installer, the pipeline creates a case folder and generates:

- Hashes: **MD5 / SHA1 / SHA256**
- File identification (`file.txt`)
- Strings extraction (`strings.txt`) with optional **lite mode**
- **capa** capability analysis (`capa.json`, `capa.txt`)
- PE metadata (`pe_metadata.json`) + LIEF metadata (`lief_metadata.json`)
- IOC extraction (`iocs.json`, `iocs.csv`)
- Reports: `report.md`, `report.html`, `report.pdf` (**WeasyPrint**)

### Installer payload extraction + subfile triage
- Extracts embedded payloads into `cases/<case>/extracted/`
- Supports recursive extraction (ZIP/7z/MSI/CAB; CAB fallback supported)
- Supports **Inno Setup** installers via `innoextract`
- Optional subfile triage into `cases/<case>/subfiles/<nn>_<filename>/`

---

## Repo Layout

- `static_triage_engine/` — engine, steps, scoring, reporting
- `scripts/` — CLI + GUI entry points and helpers
- `tools/` — tool assets (capa sigs, capa rules folder, etc.)
- `docs/` — documentation assets (screenshots)
- `cases/` — **generated output** (ignored)
- `samples/` — **do not commit samples** (ignored)
- `logs/` — runtime logs (ignored)
- `.venv/` — **Python virtual environment** (ignored)

---

## Install Ubuntu or WSL Ubuntu

### System dependencies (Ubuntu/WSL/Kali)
```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip \
  p7zip-full cabextract osslsigncode file binutils \
  libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libgdk-pixbuf-2.0-0 \
  libcairo2 libffi-dev
```

### Create and use a Python virtual environment
```bash
cd /path/to/Static-Software-Malware-Analysis
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Install Windows

### 0) Install Python 3.12 (recommended)

If you accidentally downloaded a Python ZIP (embeddable/source), it may not include an installer. The simplest Windows install path is **winget**:

```powershell
winget install -e --id Python.Python.3.12
```

Then open a new terminal and verify:
```powershell
py -3.12 -V
```

---

### Windows — PowerShell (Recommended: No Activation)

PowerShell often blocks `Activate.ps1` due to execution policy. The simplest method is to **not activate** and instead call the venv Python directly.

```powershell
# Create venv (first time only)
py -3.12 -m venv .venv

# Install dependencies (no activation needed)
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the tool:
```powershell
.\.venv\Scripts\python.exe scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

> FYSA: `source .venv/bin/activate` is Linux/WSL syntax and will not work in Windows PowerShell.

---

### Windows — PowerShell (Activation)

If you prefer activation:

```powershell
# Allow local scripts for your user (persistent)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Activate
.\.venv\Scripts\Activate.ps1

# Install deps
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

### Windows — CMD (Activation Works)

CMD activation doesn’t hit the PowerShell execution-policy wall.

Open **Command Prompt** in the repo root:
```bat
py -3.12 -m venv .venv
.\.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run:
```bat
python scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

**FYSA: deleting `.venv`**
- PowerShell:
```powershell
Remove-Item -Recurse -Force .\.venv
```
- CMD:
```bat
rmdir /s /q .venv
```

---

## capa Setup

### Install capa CLI

⚠️ **Important:** `pip install capa` may install an unrelated package. Install the official FLARE capa:

**Ubuntu/WSL**
```bash
pip install flare-capa
capa --version
```

**Windows (recommended inside `.venv`)**
```powershell
.\.venv\Scripts\python.exe -m pip install flare-capa
.\.venv\Scripts\capa.exe --version
```

---

### Install capa Rules

`capa` is separate from the **rules** it uses. Install rules into:

```
tools\capa-rules\rules\
```

Verify:
```powershell
Test-Path .\tools\capa-rules\rules
(dir .\tools\capa-rules\rules -Recurse -Filter *.yml).Count
```

---

### Install or Use capa Signatures

If capa errors about missing signatures, pass your repo sigs path:

```powershell
.\.venv\Scripts\capa.exe -r .\tools\capa-rules\rules -s .\tools\capa\sigs D:\path\to\sample.exe
```

Verify sigs exist:
```powershell
dir .\tools\capa\sigs
```

---

### Bootstrap Scripts

#### Windows (PowerShell): bootstrap capa rules
Place this script in:
```
scripts\bootstrap_capa_rules.ps1
```

Run (one-time bypass, no policy change):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap_capa_rules.ps1
```

#### Linux/WSL: bootstrap capa rules (optional)
If you maintain a bash bootstrap:
```bash
bash scripts/bootstrap_capa_rules.sh
```

---

## Running

### CLI

**Ubuntu/WSL**
```bash
source .venv/bin/activate
python3 scripts/static_triage.py /path/to/sample.exe --case MyCase --no-progress
```

**Windows PowerShell (no activation)**
```powershell
.\.venv\Scripts\python.exe scripts\static_triage.py D:\path\to\sample.exe --case MyCase --no-progress
```

### GUI (Ubuntu/WSL)
```bash
source .venv/bin/activate
python3 -m scripts.static_triage_gui
```

---

## Outputs

Each run creates:

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
  extracted/                      (if extraction enabled)
  extracted_manifest.json
  subfiles/<nn>_<filename>/       (if subfile triage enabled)
```

---

## Screenshots

![Main view](docs/screenshots/main-view.png)
![Case folder](docs/screenshots/case-folder.png)
![HTML view](docs/screenshots/html-view.png)
![HTML view 2](docs/screenshots/html-2.png)
![PDF view 2](docs/screenshots/pdf-2.png)

---

## Troubleshooting

### “running scripts is disabled” (PowerShell)
Use the **No Activation** method, or:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Dependency conflicts
Use a **fresh `.venv`** for this project. Don’t reuse a venv that already has other RE tooling installed.

### capa “default signature path doesn’t exist”
Run with your repo sigs:
```powershell
.\.venv\Scripts\capa.exe -r .\tools\capa-rules\rules -s .\tools\capa\sigs <file>
```

---

## Contributing

PRs welcome. Please avoid committing:
- malware samples
- generated `cases/` output
- large binaries

---

## License

See `LICENSE`.
