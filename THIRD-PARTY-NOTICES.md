# Third-party notices

RingForge Workbench is MIT licensed (see `LICENSE`). This file records what it
depends on and under what terms, because that is the first question a
procurement review asks and the answer should not have to be reassembled from
`requirements.txt`.

**How this was produced.** The version and licence columns below were read from
the installed distribution metadata (`importlib.metadata`) on 2026-09-04, not
transcribed from memory. Where a row says *verify*, the package was not
installed on the bench at the time and the entry reflects the upstream
project's published terms rather than metadata this repository can confirm.

**This is a record, not legal advice.** Before a commercial release, have
counsel review it — in particular the two rows flagged below.

## What the package requires

Declared in `pyproject.toml` as `dependencies`. Installed alongside the tool
and imported by it.

| Package | Version seen | Licence |
|---|---|---|
| pefile | 2023.2.7 | MIT |
| psutil | 6.1.1 | BSD-3-Clause |
| PyYAML | 6.0.3 | MIT |
| requests | 2.32.3 | Apache-2.0 |
| yara-python | 4.5.1 | Apache-2.0 |

All permissive. None imposes a condition on distributing this tool
commercially beyond attribution.

## Optional extras

Declared under `[project.optional-dependencies]`. Every one has a documented
degradation path, so a build that omits them still runs and reports the missing
capability rather than failing.

| Extra | Package | Version seen | Licence |
|---|---|---|---|
| `gui` | pillow | 12.1.1 | MIT-CMU (HPND) |
| `emulation` | capstone | 5.0.9 | BSD (per metadata) |
| `emulation` | unicorn | 2.1.4 | **see note** |
| `fuzzy` | ssdeep | not installed | **verify — see note** |
| `fuzzy` | tlsh | not installed | Apache-2.0 (verify) |
| `pdf` | weasyprint | not installed | BSD-3-Clause (verify) |
| `progress` | tqdm | not installed | MPL-2.0 / MIT (verify) |
| `dev` | pytest | 9.1.1 | MIT |

### Two rows worth a lawyer's eye

**`unicorn`.** Its PyPI metadata declares *BSD License*, but Unicorn Engine
derives from QEMU and the upstream project has historically been **GPL-2.0**.
Those cannot both be right and this repository cannot settle it. It is an
extra, used only by `scripts/` (which is not packaged), so nothing ships it
today — keep it that way until the question is answered.

**`ssdeep`.** The Python binding wraps `libfuzzy`, which is understood to be
**GPL-2.0**. Not installed here, declared as an extra, and the code returns
`None` without it. Do not bundle it without advice.

## Present in the bench, not in the package

`requirements.txt` pins the full bench environment. These are installed for
development and analysis work and are **not** dependencies of the shipped
package.

| Package | Version seen | Licence | Note |
|---|---|---|---|
| pyinstaller | 6.15.0 | GPL-2.0 | Carries an exception permitting distribution of proprietary bundled applications. Relevant only if you ship a frozen binary. |
| certifi | 2025.1.31 | MPL-2.0 | Weak, file-level copyleft. Redistribution as-is is unencumbered. |
| lief | 1.0.0 | Apache-2.0 | |
| numpy, pandas, scikit-learn | — | BSD-3-Clause | `scripts/` corpus work only. |
| urllib3 | 2.3.0 | MIT | Transitive via requests. |

**PySimpleGUI was removed from `requirements.txt` on 2026-09-04.** Version 5 is
licensed **Proprietary**. Nothing in this repository imports it; it was left
behind by a `pip freeze`. It is recorded here because it *was* in the pinned
environment, and anyone auditing an earlier commit will find it.

## External tools — invoked, never redistributed

These are separate executables the workbench shells out to. The user installs
them; this repository does not contain them, and `.gitignore` excludes their
binaries so they cannot be committed by accident.

| Tool | Licence | Redistribution |
|---|---|---|
| Procmon (Sysinternals) | Microsoft Sysinternals EULA | **Prohibited.** Ships with neither the source nor a build. `tools/Procmon.exe`, `tools/Procmon64.exe` and `tools/*.exe` are gitignored. |
| Autorunsc (Sysinternals) | Microsoft Sysinternals EULA | **Prohibited.** Same. Optional; the run reports its absence. |
| capa | Apache-2.0 | Permitted. `tools/capa-rules/` is gitignored; the rules are Apache-2.0. |
| FLOSS | Apache-2.0 | Permitted. |
| Ghidra | Apache-2.0 | Permitted. `tools/ghidra_*/` gitignored for size. |
| Sysmon | Microsoft Sysinternals EULA | **Prohibited.** Optional telemetry. |

## YARA rules

`tools/yara/rules/` is gitignored and no third-party rule set is redistributed.

**The neo23x0 `signature-base` set is licensed for non-commercial use** (CC
BY-NC 4.0 for a substantial part of it). The workbench reads whatever rules a
user points it at and ships none of them, but if a commercial product
*instructs* customers to install that set, take advice on whether that is
contributory. This is the single most likely licensing snag in the project.

Rules under `RingForge_*` are original to this repository and MIT, like the
rest of the code.

## Attribution

Where this tool's output cites a third-party detection — a capa rule, a YARA
rule name — the citation names the rule and its origin. That is deliberate: a
verdict that borrows someone else's judgement should say whose.
