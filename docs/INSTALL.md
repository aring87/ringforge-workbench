# Installing RingForge Workbench

Two ways in. Pick one:

- **The zip** — unzip and run. No Python, no virtual environment. This is what
  a release publishes.
- **From source** — a checkout and a virtual environment. Do this if you want
  to change the code, run the test suite, or use the bench scripts under
  `scripts/`.

Either way, **static analysis works immediately** and **dynamic analysis needs
a VM plus tools you install yourself**. Those are separate steps, and the
second is the longer story.

---

## Before you start

**Windows only.** Not a preference — the engine shells out to Procmon, reads
`ctypes.windll` for elevation, and the whole dynamic module observes a Windows
guest. There is no Linux or macOS path.

| | Static analysis | Dynamic analysis |
|---|---|---|
| OS | Windows 10 or 11 | Windows 10 or 11 **in a VM** |
| Administrator | Not required | Required |
| Disk | ~250 MB for the zip | ~2 GB with all tools and rule sets |
| Python | None (zip) or 3.12+ (source) | Same |
| Network | Only for VirusTotal enrichment | Contained — see below |

**Run dynamic analysis in a virtual machine you can revert.** The workbench
executes the sample. Nothing about it sandboxes anything; it observes a
detonation that really happens. Run a sample on your workstation and you have
infected your workstation.

---

## A. The zip, with no Python needed

### 1. Download and check it

Take `RingForge-v1.12.0-win64.zip` and the matching `.sha256` from the
[releases page](https://github.com/aring87/ringforge-workbench/releases).
Verify before unzipping:

```powershell
Get-FileHash .\RingForge-v1.12.0-win64.zip -Algorithm SHA256
Get-Content .\RingForge-v1.12.0-win64.zip.sha256
```

The hashes must match. **The binary is unsigned**, so this is the only
integrity check you get — see Troubleshooting for what Windows will say.

### 2. Unzip somewhere writable

```powershell
Expand-Archive .\RingForge-v1.12.0-win64.zip -DestinationPath C:\
```

That gives you `C:\RingForge\`.

**Do not use `C:\Program Files\`.** Case folders, logs and `config.json` are
written beside the executable by default, and `Program Files` is not writable
by a normal user — you would get a workbench that cannot save a case.

### 3. What you got

```text
C:\RingForge\
    ringforge-gui.exe       the workbench window
    ringforge.exe           the command line
    _internal\              frozen code and shipped data. Do not put tools here
    licenses\               licence text for every library inside the bundle
    LICENSE                 this project, MIT
    THIRD-PARTY-NOTICES.md  what it depends on and under what terms
    tools\                  capa and FLOSS in a release build, plus what you install
    cases\                  created on first run
```

`tools\VENDORED.txt` records which upstream release capa and FLOSS came from
and their SHA256. **No `tools\` directory means neither is bundled** — a
locally built zip omits any tool whose licence text was not beside it, rather
than redistributing it bare.

### 4. Run it

```powershell
cd C:\RingForge
.\ringforge-gui.exe
```

You should get a dark window titled **RingForge Workbench** with six module
cards. If it opens, the install is sound — the logo alone proves the bundle's
shipped data resolved correctly.

---

## B. From source

### 1. Get Python 3.12 or newer

```powershell
python --version
```

Anything older than 3.12, install a current Python from
<https://www.python.org/downloads/windows/> and tick **Add python.exe to PATH**.

### 2. Clone and create a virtual environment

```powershell
git clone https://github.com/aring87/ringforge-workbench.git
cd ringforge-workbench

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

**Use the virtual environment for everything after this.** A global Python
drifts, and a missing `yara-python` or `psutil` silently disables whole
collectors rather than failing loudly.

### 3. Install

```powershell
pip install -e ".[gui,dev]"
```

That is the engine, the GUI's imaging dependency, and pytest. The other extras
all have a documented fallback if you leave them out:

| Extra | Gives you | Without it |
|---|---|---|
| `gui` | Pillow, for the window's imaging | The GUI will not start |
| `pdf` | WeasyPrint, for PDF reports | Print the HTML report from a browser |
| `fuzzy` | ssdeep and TLSH fuzzy hashes | Those fields report `None` |
| `progress` | tqdm progress bars | Plain output |
| `emulation` | Unicorn and Capstone | Only `scripts/` uses these |
| `dev` | pytest | You cannot run the suite |

> Read `THIRD-PARTY-NOTICES.md` before enabling `fuzzy` or `emulation` in
> anything commercial. Both carry licence questions recorded there.

To reproduce the full bench environment instead, including the packaging
toolchain: `pip install -r requirements.txt`.

### 4. Run it

```powershell
ringforge-gui                 # the window
ringforge --help              # the command line
python -m pytest -m "not slow" -q
```

The suite should report about 1,666 passing with a couple of dozen deselected.
Tests that need `cases/` or `tools/` skip rather than fail.

### 5. Optional: build your own executable

```powershell
pip install pyinstaller
python -m PyInstaller ringforge.spec --noconfirm
```

Output is `dist\RingForge\`. The spec stamps the version and commit into the
build, because a frozen build has neither git history nor package metadata, and
every verdict records what produced it.

---

## Your first static analysis

Nothing else needs installing. Use any executable you do not mind scanning —
`C:\Windows\System32\notepad.exe` is a fine first target.

**GUI:** open **Static Analysis**, click **Browse...**, pick the file, run it.
The report opens when it finishes.

**Command line:**

```powershell
.\ringforge.exe scan C:\Windows\System32\notepad.exe --case firsttest --json
.\ringforge.exe combine cases\firsttest --pretty
```

The second command prints the banded verdict. On a clean Windows binary expect
**No Evidence** or **Insufficient Coverage**. The latter is not a failure — it
means too few collectors ran to justify a conclusion, and keeping that separate
from "nothing found" is the point of the scoring model.

Output lands in `cases\firsttest\`: the JSON verdict, an HTML report, extracted
IOCs, and whatever each collector produced.

---

## Setting up the analysis VM

Everything from here needs a guest. For static triage only, you are already
done.

### 1. Build the VM

Any hypervisor works; the host-side containment script targets VirtualBox.
Install Windows 10 or 11, then before anything else:

- Give it a **host-only adapter** for file transfer and a separate **NAT or
  bridged adapter** for the internet. Two adapters, distinct roles.
- Install the guest additions or tools.
- Set up however you will move samples in.

### 2. Get the workbench into the guest

Either unzip the release inside the guest, or clone the repo there and follow
**B. From source**. A clone is more convenient while developing; the zip is
fewer moving parts.

### 3. Quiet the machine down

In the guest, **elevated**:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\vm_hygiene.ps1
```

This disables the browser, Acrobat and OneDrive updaters, MDM enrolment and
Windows Update scanning, so a run's before/after diffs describe the sample
rather than what the machine was going to do anyway.

It is not cosmetic. A Chrome update that landed mid-detonation was reported as
two suspicious new autoruns entries, and MDM enrolment retries produced three
persistence hits per run. The script also reports Defender's posture and any
EDR agent present, both of which have to be dealt with before real samples.

### 4. Learn the containment switch

From the **host**, not the guest:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\vm_net.ps1 -Disconnect
```

Toggling the virtual cable at the hypervisor is what makes containment
enforceable. An adapter disabled inside the guest can be re-enabled by anything
running there with administrator rights, including the sample. `VBoxManage` is
outside the guest's reach. The VM does not need shutting down — link state
changes take effect immediately.

The script finds the internet-facing adapter by attachment type rather than
assuming NIC 1, so a rebuilt VM with a different adapter order cannot cause the
host-only adapter to be disconnected instead. That mistake would leave the VM
connected while appearing contained.

### 5. Snapshot before you ever detonate

Take a clean snapshot with the tools installed and containment verified, and
revert to it between samples. A detonation changes the machine, and the next
run's before/after diff is meaningless on a dirty guest.

---

## Installing the external tools

**Exact filenames, per-tool detail and verification:
[TOOL_SETUP.md](TOOL_SETUP.md).** The short version:

capa and FLOSS are Apache-2.0, so they may be redistributed, and a release
build carries both. **Check `tools\VENDORED.txt` in your copy** — it lists
what actually shipped, with the upstream version and SHA256. If it is absent,
so are they, and the bootstrap below installs capa.

Everything else may not be redistributed at all: Procmon, Autorunsc, Sysmon and
ProcDump are under the Sysinternals EULA, which prohibits it, and Npcap is
proprietary.

In the guest, **elevated**:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap_tools.ps1 -AddExclusions
```

That installs Sysmon, Wireshark/Npcap, FakeNet-NG, ProcDump, UPX and capa.
`-AddExclusions` adds Defender exclusions for `tools\` — FakeNet-NG is reliably
flagged as a HackTool and will otherwise be quarantined mid-install.

> **That switch is for the guest, and your host has its own antivirus.**
> `-AddExclusions` adds *Windows Defender* exclusions inside the VM. If the
> machine you develop on runs something else — Bitdefender, Sophos, CrowdStrike
> — Defender is usually switched off there entirely, and that product will
> quarantine capa, FLOSS and any carved payload you keep. Exclude the
> repository, `cases\`, `tools\` and wherever your VM disks live.
>
> Behavioural engines are a second list. Bitdefender's Advanced Threat Defense,
> and its equivalents, take an **application** rather than a folder, so
> `capa.exe` and `floss.exe` need naming individually — both are PyInstaller
> launchers that unpack to a temp directory and spawn a grandchild, which reads
> behaviourally as a dropper. And a block there may never reach the Windows
> event log: check the product's own notifications before deciding a collector
> is broken.

**Procmon and Autorunsc are not covered by that script.** Download the
[Sysinternals Suite](https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite)
and copy `Procmon64.exe` and `autorunsc64.exe` into `tools\`.

> **Run both once by hand first.** Each shows a EULA dialog on first launch,
> and a EULA waiting for a click is indistinguishable from a hung collector.

---

## YARA rules

In the guest:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap_yara_rules.ps1
```

Rules install to `tools\yara\rules\`. Each file is test-compiled individually
and anything that fails is quarantined to `tools\yara\_broken\`, because
`yara.compile` is all-or-nothing across the files it is handed — one rule
needing an unavailable module would otherwise mean zero scanning.

The workbench's own rules ship inside the package and are copied in as the last
step, so they survive a rule-set update.

> **Licensing.** The default set includes `Neo23x0/signature-base`, a
> substantial part of which is CC BY-NC 4.0 — **non-commercial**. Fine for
> research and internal work; take advice before shipping a commercial product
> that tells customers to install it. Choose other repositories with `-Repos`.

---

## Configuration

Most people never need this. Settings the GUI changes are saved to
`config.json` beside the executable.

Environment variables override everything, and are the right way to drive the
workbench from a pipeline:

| Variable | Sets |
|---|---|
| `TRIAGE_BASE_DIR` | The base directory, instead of the app root. `ANALYSIS_BASE_DIR` is an alias |
| `CASE_ROOT_DIR` | Where case folders are written |
| `LOGS_DIR` | Where logs go |
| `TOOLS_DIR` | Where the external tools live |
| `YARA_RULES_DIR` | The YARA rule directory |
| `CAPA_RULES_DIR` | capa rules, either the `capa-rules` folder or its `rules` subfolder |
| `CAPA_SIGS_DIR` | capa signatures, normally the `capa\sigs` folder |
| `VT_API_KEY` | Your VirusTotal key. Unset, VT enrichment reports `skipped` rather than failing |

> `VT_API_KEY` sends the sample's **SHA256**, not the file. Even so, a hash
> lookup tells VirusTotal that you have that sample. On a live incident that
> can matter.

Two roots to keep straight, because a frozen build makes them different:

- **Beside the executable** — `tools\`, `cases\`, `logs\`, `config.json`.
  Yours to manage.
- **Inside `_internal\`** — the code and the data the package ships. Putting
  tools there will not work.

---

## Your first dynamic analysis

> **Guest only. Snapshot taken. Containment verified.** In that order.

1. Open **Dynamic Analysis**.
2. Check the **Telemetry** line. Every collector you installed should read
   `ready`. Anything reading `not installed` is not where
   [TOOL_SETUP.md](TOOL_SETUP.md) says it should be.
3. Check the **containment strip** below it. If it says **NOT CONTAINED**, stop
   and fix that. It re-reads the network every four seconds, so it is telling
   you about now rather than about when the window opened.
4. Choose a sample and a timeout. Start with something benign and known.
5. **Run Dynamic Analysis.**
6. When it finishes, open **Unified Report** to pool every module that ran on
   the case and band it once.

Results go to `cases\<name>\dynamic_analysis\`: the Procmon capture, parsed
events, Sysmon telemetry, packet capture, memory dumps, the persistence diff
and an HTML report.

---

## Verifying the install

```powershell
.\ringforge.exe scan <a file> --case smoke --json
.\ringforge.exe combine cases\smoke --json --no-write
```

In the second output, check:

- **`provenance.analyzer.version`** and **`.commit`** — both non-null. Null in
  a frozen build means a verdict nobody can trace back to a build.
- **`provenance.analyzer.tools`** — every library shows a version. A `null`
  means its metadata is missing, and this field is how you know whether a
  collector could see what it claims to.
- **`provenance.collectors.yara.rules_compiled`** — greater than zero.
  `rule_file_count` counts files on disk and says nothing about whether any of
  them compiled; a rule set that never loaded read as a clean scan for a
  fortnight because that count was the only number recorded.
- **`modules_absent`** and **`uncollected_categories`** — what did not run.

From source, the suite is the better check:

```powershell
python -m pytest -m "not slow" -q
```

---

## Troubleshooting

**SmartScreen says Windows protected your PC.** The binary is unsigned. Verify
the SHA256 against the published hash, then choose **More info**, then **Run
anyway**. Signing needs a code-signing certificate this project does not carry.

**Antivirus quarantines the download.** A tool that bundles YARA and inspects
malware trips heuristics. Verify the hash, then exclude the install directory.
Inside the VM, `bootstrap_tools.ps1 -AddExclusions` does this for `tools\`
— but only for Defender. On the host, exclude it in whatever product is
actually running there, which on a developer machine is often not Defender at
all.

**A collector hangs on the first run.** Procmon and Autorunsc show a EULA
dialog on first launch. Run each once by hand.

**Collectors report ready but collect nothing.** You are not elevated. Procmon,
Sysmon, packet capture and memory dumps all need Administrator, and each says
so individually rather than failing silently.

**Every verdict comes back Insufficient Coverage.** Working as designed: too
few collectors ran to justify a conclusion. Check `modules_absent` in the JSON,
and the Telemetry line in the GUI.

**The GUI will not start.** From source, run `pip install -e ".[gui]"` — Pillow
is required and is an extra. From the zip this should not happen; check that
`licenses\` and `_internal\` survived the unzip.

**An old install reports no module named scripts.** The pipeline modules moved
into `static_triage_engine/` in v1.12.0. Pull and reinstall.

**The bootstrap cannot find the authored YARA rules.** They moved into the
package in v1.12.0. If the guest is on an older commit, pull before running the
bootstrap.

**No cases appear in the launcher.** Cases are read from the configured case
root, which defaults to `cases\` beside the executable. Installed under
`C:\Program Files\` it cannot write there — reinstall somewhere writable.
