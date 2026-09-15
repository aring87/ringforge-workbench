# Tool setup

How to take the RingForge zip from "static triage works" to "a full detonation
works", and how to check each step rather than hoping.

**Do this inside your analysis VM, not on your workstation.** Four of these
install kernel-level drivers and one installs a system-wide traffic diverter.
`bootstrap_tools.ps1` will tell you the machine looks like physical hardware if
you run it on a host, and the Dynamic Analysis window says the same thing in
red. Believe it.

---

## What is already in the zip

Both are Apache-2.0, so they can be redistributed, and a release build carries
them. Check `tools\VENDORED.txt`: it lists what actually shipped and its
SHA256, and if the file is missing then so are the tools -- a build omits any
tool whose licence text was not beside the binary rather than shipping it bare.
Where they are present there is nothing to do:

| Tool | What it gives you |
|---|---|
| **capa** | Capability detection — what the binary is *able* to do |
| **FLOSS** | Stack, tight and decoded strings that `strings` cannot see |

The bundled capa runs on its **own embedded rule set**, so it works with
nothing else installed. `scripts/bootstrap_capa_rules.ps1` installs the
external `capa-rules` tree if you would rather curate your own; when it is
present the engine passes it to capa instead, and the result records which was
used. The rules are not in the zip: their paths run long enough to break
extraction on Windows, and capa does not need them.

`tools/VENDORED.txt` in the zip records which upstream release each came from
and its SHA256.

Static analysis needs nothing else. Hashing, PE metadata, .NET metadata, IOC
extraction, YARA and the whole verdict model work on a clean machine with the
zip alone.

## What you have to install, and why it is not in the zip

| Tool | Licence | Why it is absent |
|---|---|---|
| Procmon | Sysinternals EULA | Redistribution prohibited |
| Autorunsc | Sysinternals EULA | Redistribution prohibited |
| Sysmon | Sysinternals EULA | Redistribution prohibited |
| ProcDump | Sysinternals EULA | Redistribution prohibited |
| Wireshark / Npcap | Npcap is proprietary | Redistributing it needs a paid OEM licence |
| FakeNet-NG | see upstream | Not redistributed pending a licence check |
| YARA rule sets | mixed, some non-commercial | You choose what you trust; the workbench ships only its own rules |

This is normal for the class of tool. It is the same reason Volatility, CAPE
and REMnux ask you to fetch things yourself.

---

## The fast path

From an **elevated** PowerShell, in the guest, with the zip already unpacked:

```powershell
cd C:\RingForge
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap_tools.ps1 -AddExclusions
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap_yara_rules.ps1
```

The scripts live in the source repository, not the zip — clone or download the
repo alongside it, or copy the two `.ps1` files across.

`bootstrap_tools.ps1` installs **Sysmon**, **Wireshark/Npcap**, **FakeNet-NG**,
**ProcDump**, **UPX** and **capa**. Useful switches:

- `-AddExclusions` — Defender exclusions for `tools\` and the download
  directory. FakeNet-NG is reliably flagged as a HackTool and will otherwise be
  quarantined mid-install.
- `-SkipSysmon`, `-SkipWireshark`, `-SkipFakeNet`, `-SkipProcDump` — each
  capability degrades to a reported gap rather than an error.
- `-DisableRealtimeProtection` — when exclusions are not enough.

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

**It does not install Procmon or Autorunsc.** Those two are manual, below.

---

## Manual placement

Everything is resolved relative to the executable — `app_root()` — so `tools\`
sits **beside `ringforge.exe`**, not inside `_internal\`:

```text
C:\RingForge\
    ringforge.exe
    ringforge-gui.exe
    _internal\                     frozen code and shipped data; do not put tools here
    tools\
        Procmon64.exe
        autorunsc64.exe
        sysmon64.exe
        procdump64.exe
        capa\capa.exe
        floss\floss.exe
        fakenet\fakenet.exe
        yara\rules\                downloaded rule sets
    cases\                         created on first run
```

The filenames matter. These are what the code actually looks for:

| Tool | Expected path under `tools\` | Also accepted |
|---|---|---|
| Procmon | `Procmon64.exe` | `procmon64.exe`, `procmon.exe` |
| Autorunsc | `autorunsc64.exe` | `Autorunsc64.exe` |
| Sysmon | `sysmon64.exe` | `sysmon.exe` |
| ProcDump | `procdump64.exe` | `procdump.exe` |
| FLOSS | `floss\floss.exe` | `floss.exe` |
| FakeNet-NG | `fakenet\fakenet.exe` | `fakenet.exe`, `fakenet-ng\fakenet.exe` |
| dumpcap | `dumpcap.exe` | a normal Wireshark install, or `PATH` |
| tshark | `tshark.exe` | a normal Wireshark install, or `PATH` |

**Procmon and Autorunsc**: download the Sysinternals Suite from
<https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite>, and
copy `Procmon64.exe` and `autorunsc64.exe` into `tools\`. Run each once by hand
first — both show a EULA dialog on first launch, and a EULA waiting for a click
looks exactly like a hung collector.

**Wireshark**: a normal install to `C:\Program Files\Wireshark` is found without
copying anything. If you skip it, packet capture falls back to **pktmon**, which
ships with Windows and needs no driver — lower fidelity, no third-party
dependency.

---

## YARA rules

`bootstrap_yara_rules.ps1` downloads into `tools\yara\rules\` and test-compiles
every file individually, quarantining what fails to `tools\yara\_broken\` — one
rule needing an unavailable module would otherwise take the whole set down,
because `yara.compile` is all-or-nothing across the files it is handed.

It defaults to `Neo23x0/signature-base` and `elastic/protections-artifacts`.

> **Licensing.** A substantial part of the Neo23x0 set is CC BY-NC 4.0 —
> non-commercial. Fine for research and internal work; take advice before using
> it in a commercial product. Choose different repos with `-Repos`.

The workbench's own rules ship inside the package and are copied into the
downloaded set as its last step, so they survive a rule-set update.

---

## Verifying it worked

**In the GUI.** Open **Dynamic Analysis**. The Telemetry line reads out each
collector:

```
Sysmon: ready | Capture: ready | FakeNet: ready | Memory: ready | Mem YARA: ready
```

`not installed` means the file is not where the table above says. The
containment strip below it re-reads the network every four seconds — if it says
**NOT CONTAINED**, fix that before detonating anything.

**On the command line**, against a file you do not mind scanning:

```powershell
.\ringforge.exe scan C:\samples\benign.exe --case smoke --json
.\ringforge.exe combine cases\smoke --json --no-write
```

In the second output, check `provenance.collectors.yara`:

- `rules_compiled` greater than zero means the rule set loaded. `rule_file_count`
  alone does **not** — it counts files on disk, and a set that never compiled
  reads as a clean scan.
- `error` must be `null`.

A band of **Insufficient Coverage** on a real sample usually means a collector
is missing rather than that the sample is clean. That distinction is the entire
point of the verdict model — check `modules_absent` and `uncollected_categories`
before believing a quiet result.

---

## Running elevated

Procmon, Sysmon, packet capture and process memory dumps all need
Administrator. Unelevated, each reports the reason rather than failing silently
— for example *"ProcDump found, but the workbench is not running as
Administrator"*. If several collectors report ready and collect nothing, check
elevation first.
