# Static Software / Malware Analysis — Static Triage Pipeline

A static triage pipeline for Windows executables/installers (EXE/DLL) that produces SOC-ticket style reports and structured case artifacts for investigation and training.

## What it does

Given a Windows EXE/DLL (including installers), the pipeline creates a case folder and generates:

- Hashes (MD5/SHA1/SHA256)
- `file` output (`file.txt`)
- strings (`strings.txt`) with optional lite mode
- capa analysis (`capa.json`, `capa.txt`)
- PE metadata (`pe_metadata.json`) + LIEF metadata (`lief_metadata.json`)
- IOC extraction (`iocs.json`, `iocs.csv`)
- Reports: `report.md`, `report.html`, `report.pdf` (WeasyPrint)

### Installer payload extraction + subfile triage
- Extracts embedded payloads into `cases/<case>/extracted/`
- Supports recursive extraction (CAB/MSI/ZIP/7z)
- Supports Inno Setup installers via `innoextract`
- Triages up to N extracted PE payloads into `cases/<case>/subfiles/<nn>_<filename>/`
- Rollups include:
  - **Top scoring embedded payloads**
  - **Attention** list (score threshold / unsigned / high-signal)

### Scoring / verdict
- Installer-aware scoring to reduce false positives on legitimate installers
- Authenticode-aware scoring (valid signature + timestamp reduces risk unless high-signal behaviors present)

---

## Repository layout

Tracked:
- `static_triage_engine/` — core engine + steps + scoring + reporting
- `scripts/` — CLI + GUI + helper modules
- `tools/capa/sigs/` — capa signature files (`*.sig`)
- `triage_inbox.py` — optional helper

Not tracked (by design):
- `tools/capa-rules/` — download separately
- `samples/` — do not commit binaries
- `cases/` — do not commit artifacts/reports
- `.venv/` — do not commit environments
- `logs/` — do not commit runtime logs

---

## Quick start (Ubuntu)

### System dependencies
```bash
sudo apt update
sudo apt install -y p7zip-full cabextract osslsigncode file binutils \
  libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libgdk-pixbuf-2.0-0 \
  libcairo2 libffi-dev
Python environment
cd ~/analysis   # or wherever you cloned the repo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Inno Setup support (recommended): build innoextract from source

Ubuntu repo versions can lag. For best compatibility with modern Inno installers:

sudo apt update
sudo apt install -y git cmake g++ make libboost-all-dev libssl-dev zlib1g-dev liblzma-dev

cd /tmp
rm -rf innoextract
git clone https://github.com/dscharrer/innoextract.git
cd innoextract
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
sudo cmake --install build

which innoextract
innoextract --version 2>/dev/null || innoextract -v 2>/dev/null
Quick start (Windows)
Option A (recommended): run the pipeline in WSL (Ubuntu)

This project is designed primarily for Linux tooling (7z, osslsigncode, innoextract, WeasyPrint deps).

Install WSL + Ubuntu

Clone the repo inside Ubuntu (WSL)

Follow the Ubuntu instructions above

You can store samples on the Windows drive and access them from WSL:

Windows: D:\Projects\...

WSL: /mnt/d/Projects/...

Option B: Windows-only mode (limited)

You can still use parts of the pipeline on Windows if you install equivalents:

7-Zip CLI (7z.exe) in PATH

Python packages

capa

(Authenticode verification differs; osslsigncode is Linux-focused)

WeasyPrint is harder on Windows due to dependencies

If you want “Windows-native” support, WSL is the simplest and most reliable approach.

capa setup (rules + sigs)
1) capa rules (NOT tracked in this repo)

Create the directory:

mkdir -p tools/capa-rules

Then download capa rules into tools/capa-rules/ (clone the official capa-rules repo or use the rules archive).
The engine expects many .yml/.yaml rules under this directory.

2) capa sigs (tracked here)

Signatures are stored in:

tools/capa/sigs/*.sig

Running
CLI (Ubuntu/WSL)
source .venv/bin/activate
python3 scripts/static_triage.py /path/to/sample.exe --case MyCase --no-progress

Useful flags:

# Fast triage
python3 scripts/static_triage.py /path/to/sample.exe --case MyCase --no-progress --strings-lite --subfile-limit 5

# Deep triage
python3 scripts/static_triage.py /path/to/sample.exe --case MyCase --no-progress --subfile-limit 25

# Hash-only
python3 scripts/static_triage.py /path/to/sample.exe --case MyCase --no-progress --no-extract --no-subfiles --no-strings
GUI (Ubuntu/WSL)
source .venv/bin/activate
python3 -m scripts.static_triage_gui

GUI includes:

Presets: Fast Triage / Deep Triage / Hash Only

Advanced toggle (override preset values)

Warning if strings are skipped (IOC extraction depends on strings output)

Outputs

Each run creates:

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
Security notes / safe handling

Do NOT commit malware samples or case outputs into Git.

Use isolated environments for analysis (VM/WSL recommended).

Treat unknown installers as potentially malicious until validated.

License / Attribution

This project integrates or depends on third-party tools/rules (e.g., capa rules/signatures).
Follow each upstream license for redistribution and usage.