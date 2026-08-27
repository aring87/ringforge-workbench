<#
.SYNOPSIS
  Installs the tier-1 dynamic analysis telemetry tools into an analysis VM.

.DESCRIPTION
  Sets up the tools that close the gaps Procmon cannot see:

    Sysmon        process injection, hollowing, image loads, WMI, DNS queries
    Wireshark     dumpcap + tshark, and the Npcap driver, for full packet capture
    FakeNet-NG    a simulated internet so samples proceed through their real logic
    ProcDump      process memory images, for scanning what a packer unpacked
    Crash dumps   a full image of any process that faults, which is the only
                  way to capture one that dies between dump offsets

  Scanning those images also needs YARA rules, which this script does not
  install. Run scripts\bootstrap_yara_rules.ps1 for those.

  The first three install kernel-level drivers, and FakeNet installs a system-wide
  traffic diverter. This script is intended for a disposable analysis VM and
  refuses to run on what looks like physical hardware unless -Force is given.

  After installing, it runs the workbench's own preflight checks so you can see
  exactly what the Dynamic Analysis window will report.

  Recommended order of operations:
    1) Snapshot the clean VM
    2) Run this script
    3) Snapshot again as the "tooling installed" baseline
    4) Detonate samples, reverting to the step-3 snapshot between runs

.PARAMETER SkipSysmon
  Do not install Sysmon.

.PARAMETER SkipWireshark
  Do not install Wireshark/Npcap.

.PARAMETER SkipFakeNet
  Do not install FakeNet-NG.

.PARAMETER SkipProcDump
  Do not install ProcDump.

.PARAMETER SysmonConfigUrl
  Sysmon configuration to install. Defaults to the SwiftOnSecurity config, which
  is a well-tested general-purpose baseline. ProcessTampering (Event 25) is
  switched on afterwards -- the shipped config leaves it commented out, and
  without it process hollowing is invisible.

.PARAMETER CrashDumpFolder
  Where Windows writes a full memory dump when a process crashes. Configured
  alongside ProcDump, because a process that lives less time than the gap
  between dump offsets can only be captured at the fault.

.PARAMETER AddExclusions
  Exclude the tools and temp directories from Defender before downloading.
  FakeNet-NG is reliably flagged as a HackTool and is otherwise quarantined on
  arrival -- or refused mid-download, since Defender scans the file as it is
  written. Applied through Add-MpPreference where that works and through the
  Group Policy registry otherwise, because a debloated image is missing the
  Defender WMI namespace the cmdlet needs. Appropriate inside a disposable
  analysis VM and nowhere else.

.PARAMETER DisableRealtimeProtection
  Turn Defender's real-time protection off by policy. A bigger hammer than
  -AddExclusions, and needed when exclusions are not enough -- most obviously
  when Defender has already quarantined a tool. Requires a reboot to take
  effect. Appropriate inside a disposable analysis VM and nowhere else.

.PARAMETER SkipUpx
  Do not install UPX. UPX is only needed to build the packed positive control in
  test_specs\upx_control\; nothing in a detonation uses it.

.PARAMETER SkipScriptBlockLogging
  Do not enable PowerShell ScriptBlock logging. Leaving it off means a sample
  that ran heavily obfuscated PowerShell and one that ran none produce identical
  output, so this is worth doing before a run rather than after a dull one.

.PARAMETER Force
  Proceed even when this does not look like a virtual machine. Use only if you
  are certain; see the warning above.

.PARAMETER KeepTemp
  Keep downloaded files for debugging.
#>

[CmdletBinding()]
param(
  [switch]$SkipSysmon,
  [switch]$SkipWireshark,
  [switch]$SkipFakeNet,
  [switch]$SkipProcDump,
  [switch]$SkipUpx,
  [switch]$SkipCapa,
  [string]$CapaRepo = "mandiant/capa",
  [switch]$SkipScriptBlockLogging,
  [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
  [string]$CrashDumpFolder = "C:\werdumps",
  [string]$FakeNetRepo = "mandiant/flare-fakenet-ng",
  [string]$UpxRepo = "upx/upx",
  [switch]$AddExclusions,
  [switch]$DisableRealtimeProtection,
  [switch]$Force,
  [switch]$KeepTemp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Step($msg) { Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Magenta }

function Get-ScriptDir {
  if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }
  $inv = $MyInvocation.MyCommand.Path
  if ($inv -and $inv.Trim().Length -gt 0) { return (Split-Path -Parent $inv) }
  return (Get-Location).Path
}

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VirtualMachineEvidence {
  <#
    Collects every independent hint that this is a VM and returns them all.

    Reading only Win32_ComputerSystem is not enough: analysis VMs are commonly
    hardened against anti-VM evasion by spoofing their DMI/SMBIOS strings, which
    also defeats the naive check. Guest-additions services and virtual device
    names survive that hardening, so several sources are consulted and any one
    hit is sufficient.
  #>
  # Deliberately vendor-specific. A bare "Virtual" matches a mounted VHD and
  # "Microsoft Virtual Disk" on ordinary physical machines, and matching those
  # would turn this guard into a rubber stamp.
  $pattern = 'VirtualBox|VBOX|VMware|QEMU|Xen|innotek|Parallels|Bochs'
  $evidence = @()

  # 1) DMI / SMBIOS identity strings.
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $value = "{0} {1}" -f $cs.Manufacturer, $cs.Model
    if ($value -match $pattern) { $evidence += "ComputerSystem: $value" }
  } catch { }

  try {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $value = "{0} {1} {2}" -f $bios.Manufacturer, $bios.Version, $bios.SerialNumber
    if ($value -match $pattern) { $evidence += "BIOS: $value" }
  } catch { }

  try {
    $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
    $value = "{0} {1}" -f $product.Vendor, $product.Name
    if ($value -match $pattern) { $evidence += "SystemProduct: $value" }
  } catch { }

  # Hyper-V guests report this exact pair, and a Hyper-V *host* does not.
  # The vmic* integration services are no use here: Windows ships them on
  # hosts too, so their presence proves nothing.
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($cs.Manufacturer -eq "Microsoft Corporation" -and $cs.Model -eq "Virtual Machine") {
      $evidence += "Hyper-V guest"
    }
  } catch { }

  # 2) Guest-additions services. These survive DMI spoofing.
  # Only guest-side packages are listed: VirtualBox's host install uses
  # VBoxSDS/VBoxSVC, which are deliberately absent from this list.
  $guestServices = @(
    "VBoxService", "VBoxGuest", "VBoxSF", "VBoxMouse",
    "VMTools", "VMwareTools", "vmhgfs", "vmmouse", "vmrawdsk",
    "qemu-ga", "xenbus", "xensvc"
  )
  foreach ($name in $guestServices) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $svc) { $evidence += "Service: $name" }
  }

  # 3) Virtual hardware.
  try {
    foreach ($disk in @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop)) {
      if ($disk.Model -and $disk.Model -match $pattern) {
        $evidence += "Disk: $($disk.Model)"
      }
    }
  } catch { }

  try {
    foreach ($video in @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop)) {
      if ($video.Name -and $video.Name -match $pattern) {
        $evidence += "Video: $($video.Name)"
      }
    }
  } catch { }

  # 4) Guest driver files on disk. vmci.sys is excluded: VMware Workstation
  # installs it on the host as well, so it does not imply a guest.
  $driverDir = Join-Path $env:SystemRoot "System32\drivers"
  foreach ($driver in @("VBoxGuest.sys", "VBoxMouse.sys", "VBoxSF.sys",
                        "vmhgfs.sys", "vmmouse.sys", "vm3dmp.sys")) {
    if (Test-Path -LiteralPath (Join-Path $driverDir $driver)) {
      $evidence += "Driver: $driver"
    }
  }

  return @($evidence | Select-Object -Unique)
}

function Get-ServiceState {
  param([Parameter(Mandatory=$true)][string]$Name)
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $svc) { return "" }
  return $svc.Status.ToString()
}

function Install-Sysmon {
  param(
    [Parameter(Mandatory=$true)][string]$ToolsDir,
    [Parameter(Mandatory=$true)][string]$TempDir,
    [Parameter(Mandatory=$true)][string]$ConfigUrl
  )

  Write-Step "Sysmon"

  $zip = Join-Path $TempDir "Sysmon.zip"
  $extract = Join-Path $TempDir "sysmon"

  Write-Info "Downloading Sysmon from Sysinternals..."
  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath $extract -Force

  $exe = Get-ChildItem -Path $extract -Filter "Sysmon64.exe" -Recurse -ErrorAction SilentlyContinue |
         Select-Object -First 1
  if (-not $exe) {
    $exe = Get-ChildItem -Path $extract -Filter "Sysmon.exe" -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
  }
  if (-not $exe) { throw "Could not find Sysmon executable in the downloaded archive." }

  # Keep a copy under tools\ so the workbench preflight can find the binary
  # even when the service is not running.
  $target = Join-Path $ToolsDir $exe.Name
  Copy-Item -LiteralPath $exe.FullName -Destination $target -Force
  Write-Ok "Sysmon binary: $target"

  $configPath = Join-Path $ToolsDir "sysmonconfig.xml"
  Write-Info "Downloading Sysmon configuration..."
  try {
    Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath
    Write-Ok "Config: $configPath"
    Enable-ProcessTampering -ConfigPath $configPath
  } catch {
    Write-Warn "Could not download the Sysmon config: $($_.Exception.Message)"
    Write-Warn "Installing with the built-in default config instead (noisier, fewer events)."
    $configPath = ""
  }

  $existing = Get-ServiceState -Name "Sysmon64"
  if (-not $existing) { $existing = Get-ServiceState -Name "Sysmon" }

  if ($existing) {
    Write-Info "Sysmon already installed (service state: $existing). Updating configuration..."
    if ($configPath) {
      & $target -accepteula -c $configPath | Out-Null
    }
  } else {
    Write-Info "Installing the Sysmon driver and service..."
    if ($configPath) {
      & $target -accepteula -i $configPath | Out-Null
    } else {
      & $target -accepteula -i | Out-Null
    }
  }

  Start-Sleep -Seconds 3
  $state = Get-ServiceState -Name "Sysmon64"
  if (-not $state) { $state = Get-ServiceState -Name "Sysmon" }

  if ($state -eq "Running") {
    Write-Ok "Sysmon service is running."
  } else {
    Write-Warn "Sysmon service state is '$state'. Injection and WMI telemetry will be unavailable."
  }
}

function Enable-ProcessTampering {
  <#
    .SYNOPSIS
      Switch on Sysmon Event 25 in a downloaded configuration.

    .DESCRIPTION
      SwiftOnSecurity's config ships ProcessTampering commented out, so a
      freshly bootstrapped VM cannot see process hollowing at all. That is not
      a small gap: Sysmon's other injection event is Event 8,
      CreateRemoteThread, and hollowing does not use it -- NtUnmapViewOfSection,
      WriteProcessMemory and SetThreadContext raise nothing.

      A Formbook sample hollowed RegSvcs.exe on this workbench and the run
      reported injection_events: 0. The technique was invisible, and the empty
      result looked exactly like a sample that had not injected.

      Enabled here rather than by hand because this function overwrites the
      config on every run: a change made in the guest survives only until the
      next bootstrap, and would then vanish with nothing to say it had gone.

      The tooling is excluded. ProcDump suspends and reads process memory,
      which is the behaviour the event exists to catch.
  #>
  param([string]$ConfigPath)

  if (-not (Test-Path $ConfigPath)) { return }

  $xml = Get-Content $ConfigPath -Raw

  # Comments are stripped before testing. The shipped config *documents*
  # ProcessTampering in a commented-out example, so a plain text match finds it
  # and concludes there is nothing to do -- which is exactly what happened the
  # first time this was done by hand.
  $stripped = [regex]::Replace($xml, '(?s)<!--.*?-->', '')
  if ($stripped -match '<ProcessTampering') {
    Write-Info "Sysmon config already enables ProcessTampering (Event 25)."
    return
  }

  if ($xml -notmatch '</EventFiltering>') {
    Write-Warn "Sysmon config has no </EventFiltering>; leaving Event 25 disabled."
    return
  }

  $block = @'
  <RuleGroup name="" groupRelation="or">
    <ProcessTampering onmatch="exclude">
      <Image condition="image">Sysmon64.exe</Image>
      <Image condition="image">procdump64.exe</Image>
    </ProcessTampering>
  </RuleGroup>
</EventFiltering>
'@

  try {
    Set-Content -LiteralPath $ConfigPath -Value $xml.Replace('</EventFiltering>', $block) -Encoding utf8
    Write-Ok "Enabled ProcessTampering (Event 25) for process-hollowing detection."
  } catch {
    Write-Warn "Could not enable ProcessTampering: $($_.Exception.Message)"
  }
}

function Enable-CrashDumps {
  <#
    .SYNOPSIS
      Make Windows write a full memory dump when any process crashes.

    .DESCRIPTION
      The dump watcher works on a schedule, and a hollowed process that lives
      four seconds falls between offsets. Two Formbook runs produced nine dumps
      between them and no image of RegSvcs.exe after the payload was written
      into it -- while Windows was logging the crash and discarding the memory,
      because local dumps are off by default and only Report.wer gets written.

      A crash dump is taken at the one moment worth having: after the payload
      was written and while it was executing.

      Machine-wide and correct only for a disposable analysis VM. DumpCount
      bounds retention; DumpType 2 is full memory, and a minidump may omit the
      injected region, which is the whole point of collecting it.
  #>
  param([string]$DumpFolder = "C:\werdumps", [int]$DumpCount = 20)

  Write-Step "Crash dumps"

  $key = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
  try {
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "DumpFolder" -PropertyType ExpandString -Value $DumpFolder -Force | Out-Null
    New-ItemProperty -Path $key -Name "DumpType" -PropertyType DWord -Value 2 -Force | Out-Null
    New-ItemProperty -Path $key -Name "DumpCount" -PropertyType DWord -Value $DumpCount -Force | Out-Null
    New-Item -ItemType Directory -Path $DumpFolder -Force | Out-Null
    Write-Ok "Full crash dumps will be written to $DumpFolder (keeping $DumpCount)."
  } catch {
    Write-Warn "Could not configure crash dumps: $($_.Exception.Message)"
    Write-Warn "A crashing payload will leave metadata and no memory image."
  }
}

function Install-ProcDump {
  param(
    [Parameter(Mandatory=$true)][string]$ToolsDir,
    [Parameter(Mandatory=$true)][string]$TempDir
  )

  Write-Step "ProcDump"

  $target = Join-Path $ToolsDir "procdump64.exe"
  if (Test-Path -LiteralPath $target) {
    Write-Ok "ProcDump already present: $target"
    return
  }

  $zip = Join-Path $TempDir "Procdump.zip"
  $extract = Join-Path $TempDir "procdump"

  Write-Info "Downloading ProcDump from Sysinternals..."
  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" -OutFile $zip
  Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

  # procdump64.exe specifically: the 32-bit build cannot dump a 64-bit process,
  # and a partial dump of the wrong bitness scans as though the sample did
  # nothing.
  $exe = Get-ChildItem -Path $extract -Filter "procdump64.exe" -Recurse -ErrorAction SilentlyContinue |
         Select-Object -First 1

  if (-not $exe) {
    Write-Warn "procdump64.exe was not found in the downloaded archive."
    Write-Warn "Download it manually from https://learn.microsoft.com/sysinternals/downloads/procdump"
    Write-Warn "and place procdump64.exe in $ToolsDir"
    return
  }

  Copy-Item -LiteralPath $exe.FullName -Destination $target -Force
  Write-Ok "ProcDump binary: $target"

  # ProcDump prompts for the EULA on first run and would otherwise block the
  # first detonation on a dialog nobody is watching. The workbench passes
  # -accepteula on every invocation, but accepting it once here also covers
  # manual use.
  try {
    & $target -accepteula -? | Out-Null
  } catch {
    Write-Verbose "ProcDump EULA pre-accept returned: $($_.Exception.Message)"
  }
}

function Add-MachinePathEntry {
<#
.SYNOPSIS
  Put a directory on the machine PATH, and on this session's PATH.

.DESCRIPTION
  capa used to arrive only via `pip install flare-capa` into the project venv,
  which put capa.exe in .venv\Scripts -- a directory that is on PATH only while
  the venv is activated. A fresh PowerShell window could not see it.

  That failed silently and expensively. Across a 229-sample malware corpus capa
  failed on 194 of them, 182 with "the system cannot find the file specified",
  and the engine recorded every one as a completed analysis: the scorer read
  "capa found no techniques" where the truth was "capa was never started". The
  measurement that came out of it was wrong by a factor of four.

  A machine PATH entry is the fix, because it does not depend on how the shell
  was opened.
#>
  param([Parameter(Mandatory=$true)][string]$Directory)

  if (-not (Test-Path -LiteralPath $Directory)) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
  }
  $resolved = (Resolve-Path -LiteralPath $Directory).Path

  $current = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $entries = @($current -split ';' | Where-Object { $_ -ne '' })

  if ($entries -contains $resolved) {
    Write-Ok "Already on the machine PATH: $resolved"
  } else {
    [Environment]::SetEnvironmentVariable(
      "Path", (($entries + $resolved) -join ';'), "Machine")
    Write-Ok "Added to the machine PATH: $resolved"
    Write-Info "New shells pick this up automatically; this one is updated below."
  }

  # The current session does not inherit a machine change, and the very next
  # thing anyone does is run the tool.
  if (($env:Path -split ';') -notcontains $resolved) {
    $env:Path = "$env:Path;$resolved"
  }
}

function Install-Capa {
<#
.SYNOPSIS
  Install the standalone capa binary into tools\capa and put it on PATH.

.DESCRIPTION
  The standalone release, not `pip install flare-capa`. A pip install lands in
  whichever Python is active and disappears when it is not; the released binary
  has no interpreter to lose track of, and sits beside the signatures the engine
  already expects at tools\capa\sigs.

  Rules are separate. Run bootstrap_capa_rules.ps1 for those.
#>
  param(
    [Parameter(Mandatory=$true)][string]$ToolsDir,
    [Parameter(Mandatory=$true)][string]$TempDir,
    [string]$Repo = "mandiant/capa"
  )

  Write-Step "capa"

  $capaDir = Join-Path $ToolsDir "capa"
  $target  = Join-Path $capaDir "capa.exe"

  if ((Test-Path -LiteralPath $target) -and -not $Force) {
    Write-Ok "capa already present: $target"
    Add-MachinePathEntry -Directory $capaDir
    return
  }

  $headers = @{ "User-Agent" = "bootstrap_tools.ps1" }
  try {
    $release = Invoke-RestMethod -Headers $headers `
      -Uri ("https://api.github.com/repos/{0}/releases/latest" -f $Repo)
  } catch {
    Write-Warn "Could not reach the GitHub API: $($_.Exception.Message)"
    Write-Warn "Download capa manually from https://github.com/$Repo/releases and place capa.exe in $capaDir"
    return
  }

  $asset = @($release.assets) |
    Where-Object { $_.name -match '(?i)windows' -and $_.name -match '(?i)\.zip$' } |
    Select-Object -First 1

  if (-not $asset) {
    Write-Warn "No Windows asset in $Repo release $($release.tag_name)."
    Write-Warn "Download capa manually from https://github.com/$Repo/releases and place capa.exe in $capaDir"
    return
  }

  $zip     = Join-Path $TempDir $asset.name
  $extract = Join-Path $TempDir "capa"

  Write-Info ("Downloading {0} ({1})..." -f $asset.name, $release.tag_name)
  try {
    Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $zip
    if (Test-Path -LiteralPath $extract) { Remove-Item -Recurse -Force $extract }
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
  } catch {
    Write-Warn "Download or extract failed: $($_.Exception.Message)"
    return
  }

  $exe = Get-ChildItem -Path $extract -Recurse -Filter "capa.exe" |
    Select-Object -First 1
  if (-not $exe) {
    Write-Warn "capa.exe not found inside $($asset.name)."
    return
  }

  New-Item -ItemType Directory -Force -Path $capaDir | Out-Null
  Copy-Item -LiteralPath $exe.FullName -Destination $target -Force
  Write-Ok "capa installed: $target"

  Add-MachinePathEntry -Directory $capaDir

  # **Prove it resolves by name.** The whole failure this replaces was capa
  # being present on disk and not findable, so "the file exists" is not the
  # check that matters.
  $found = Get-Command capa -ErrorAction SilentlyContinue
  if ($found) {
    Write-Ok "capa resolves on PATH: $($found.Source)"
    try {
      $version = & capa --version 2>&1 | Select-Object -First 1
      Write-Ok "capa reports: $version"
    } catch {
      Write-Warn "capa is on PATH but would not run: $($_.Exception.Message)"
    }
  } else {
    Write-Warn "capa.exe is installed but does not resolve by name in this session."
  }
}

function Install-Upx {
  param(
    [Parameter(Mandatory=$true)][string]$ToolsDir,
    [Parameter(Mandatory=$true)][string]$TempDir,
    [Parameter(Mandatory=$true)][string]$Repo
  )

  Write-Step "UPX"

  # UPX is not part of a detonation. It exists to build the positive control
  # described in test_specs\upx_control\, which is the only thing that shows the
  # ruleset covers a payload that is compressed at rest -- the case the memory
  # canary deliberately does not test.
  $target = Join-Path $ToolsDir "upx.exe"
  if (Test-Path -LiteralPath $target) {
    Write-Ok "UPX already present: $target"
    return
  }

  $headers = @{ "User-Agent" = "bootstrap_tools.ps1" }

  try {
    $release = Invoke-RestMethod -Headers $headers -Uri ("https://api.github.com/repos/{0}/releases/latest" -f $Repo)
  } catch {
    Write-Warn "Could not query the UPX release API: $($_.Exception.Message)"
    Write-Warn "Download upx.exe manually from https://github.com/$Repo/releases and place it in $ToolsDir"
    return
  }

  # win64 specifically. UPX will happily refuse a 64-bit input if only the 32-bit
  # build is present, and the failure reads as "packing did not work" rather than
  # "wrong packer build".
  $asset = @($release.assets) |
           Where-Object { $_.name -match "win64\.zip$" } |
           Select-Object -First 1

  if (-not $asset) {
    Write-Warn "No win64 archive in the latest UPX release."
    Write-Warn "Download upx.exe manually from https://github.com/$Repo/releases and place it in $ToolsDir"
    return
  }

  $zip = Join-Path $TempDir $asset.name
  $extract = Join-Path $TempDir "upx"

  Write-Info ("Downloading {0} ({1})..." -f $asset.name, $release.tag_name)
  Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $zip
  Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

  $exe = Get-ChildItem -Path $extract -Filter "upx.exe" -Recurse -ErrorAction SilentlyContinue |
         Select-Object -First 1

  if (-not $exe) {
    Write-Warn "upx.exe was not found in the downloaded archive."
    return
  }

  Copy-Item -LiteralPath $exe.FullName -Destination $target -Force
  Write-Ok "UPX binary: $target"
}

function Enable-ScriptBlockLogging {
  Write-Step "PowerShell ScriptBlock logging"

  # Set through Group Policy rather than the per-user key, for the same reason
  # the Defender settings are: this image is missing CIM namespaces, and the
  # policy path is the one that reliably holds.
  #
  # Worth enabling before any run rather than after a disappointing one: with it
  # off, a sample that ran heavily obfuscated PowerShell and a sample that ran
  # none at all produce identical output.
  $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

  try {
    if (-not (Test-Path -LiteralPath $key)) {
      New-Item -Path $key -Force | Out-Null
    }
    New-ItemProperty -Path $key -Name "EnableScriptBlockLogging" `
                     -Value 1 -PropertyType DWord -Force | Out-Null

    # Deliberately NOT enabling EnableScriptBlockInvocationLogging: it records
    # every block start and stop, which buries the script text this is for.
    Write-Ok "ScriptBlock logging enabled (Event ID 4104)."
    Write-Info "Script text is recorded after the engine deobfuscates it, so"
    Write-Info "encoded and packed PowerShell is captured as what actually ran."
  } catch {
    Write-Warn "Could not enable ScriptBlock logging: $($_.Exception.Message)"
    return
  }

  $channel = "Microsoft-Windows-PowerShell/Operational"
  try {
    & wevtutil gl $channel | Out-Null
    if ($LASTEXITCODE -eq 0) {
      Write-Ok "Channel available: $channel"
    } else {
      Write-Warn "Channel $channel is not available on this host."
    }
  } catch {
    Write-Warn "Could not query $channel."
  }
}

function Install-Wireshark {
  param([Parameter(Mandatory=$true)][string]$TempDir)

  Write-Step "Wireshark / Npcap"

  $existing = Get-Command "dumpcap.exe" -ErrorAction SilentlyContinue
  if (-not $existing) {
    foreach ($base in @("C:\Program Files\Wireshark", "C:\Program Files (x86)\Wireshark")) {
      $candidate = Join-Path $base "dumpcap.exe"
      if (Test-Path -LiteralPath $candidate) { $existing = $candidate; break }
    }
  }

  if ($existing) {
    Write-Ok "Wireshark already installed; skipping."
    return
  }

  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if ($winget) {
    Write-Info "Installing Wireshark via winget..."
    try {
      & $winget.Source install --id WiresharkFoundation.Wireshark `
        --accept-package-agreements --accept-source-agreements --silent
      Write-Ok "Wireshark installed."
      Write-Warn "Npcap may have prompted separately; confirm it is installed."
      return
    } catch {
      Write-Warn "winget install failed: $($_.Exception.Message)"
    }
  }

  Write-Warn "Automated install unavailable."
  Write-Warn "Install Wireshark manually from https://www.wireshark.org/download.html"
  Write-Warn "and ensure the bundled Npcap driver is selected. Packet capture needs both."
}

function Install-FakeNet {
  param(
    [Parameter(Mandatory=$true)][string]$ToolsDir,
    [Parameter(Mandatory=$true)][string]$TempDir,
    [Parameter(Mandatory=$true)][string]$Repo
  )

  Write-Step "FakeNet-NG"

  $headers = @{ "User-Agent" = "bootstrap_tools.ps1" }
  Write-Info "Querying latest release of $Repo..."

  try {
    $rel = Invoke-RestMethod -Headers $headers -Uri ("https://api.github.com/repos/{0}/releases/latest" -f $Repo)
  } catch {
    Write-Warn "Could not query the FakeNet-NG release API: $($_.Exception.Message)"
    Write-Warn "Download it manually from https://github.com/$Repo/releases and extract to tools\fakenet\"
    return
  }

  $assets = @($rel.assets)
  $asset = $null
  if ($assets.Count -gt 0) {
    $asset = @($assets | Where-Object { $_.name -match '\.zip$' } | Select-Object -First 1)[0]
  }

  if (-not $asset) {
    Write-Warn "No zip asset found in release $($rel.tag_name)."
    Write-Warn "Download it manually from https://github.com/$Repo/releases and extract to tools\fakenet\"
    return
  }

  Write-Info "Downloading $($asset.name)..."
  $zip = Join-Path $TempDir $asset.name
  Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $zip

  $extract = Join-Path $TempDir "fakenet_extract"
  Expand-Archive -Path $zip -DestinationPath $extract -Force

  $exe = Get-ChildItem -Path $extract -Filter "fakenet.exe" -Recurse -ErrorAction SilentlyContinue |
         Select-Object -First 1
  if (-not $exe) {
    Write-Warn "fakenet.exe not found inside the release archive; extracting as-is."
    $exe = $null
  }

  $dest = Join-Path $ToolsDir "fakenet"
  if (Test-Path -LiteralPath $dest) {
    Remove-Item -Recurse -Force -LiteralPath $dest
  }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null

  if ($exe) {
    # Copy the whole folder containing fakenet.exe: it needs its configs and DLLs.
    Copy-Item -Recurse -Force -Path (Join-Path $exe.Directory.FullName "*") -Destination $dest
  } else {
    Copy-Item -Recurse -Force -Path (Join-Path $extract "*") -Destination $dest
  }

  # Antivirus commonly quarantines fakenet.exe between extraction and this
  # check, since a traffic diverter looks exactly like a HackTool.
  Start-Sleep -Seconds 2
  $installed = Join-Path $dest "fakenet.exe"
  if (Test-Path -LiteralPath $installed) {
    Write-Ok "FakeNet-NG: $installed"
  } else {
    Write-Warn "fakenet.exe is not present after extraction."
    Write-Warn "Antivirus most likely quarantined it: FakeNet-NG diverts traffic,"
    Write-Warn "so it is classed as a HackTool. This is an expected false positive."
    Write-Warn "Add a Defender exclusion for the tools directory and re-run:"
    Write-Warn "  Add-MpPreference -ExclusionPath '$ToolsDir'"
  }
}

function Add-DefenderExclusions {
  <#
    Exclude paths from Defender, by whichever mechanism this image supports.

    Add-MpPreference alone is not enough. It talks to the Defender WMI provider,
    and debloated Windows images -- the usual analysis VM base -- are missing the
    Root\Microsoft\Windows\Defender namespace entirely, so the cmdlet fails with
    "Invalid namespace". Since -AddExclusions is advertised as the fix for
    FakeNet being quarantined, a silent skip there means the flag does nothing on
    exactly the machines that need it.

    The Group Policy keys do not go through that provider, so they work where the
    cmdlet cannot. Both are attempted: the cmdlet applies immediately, the policy
    keys survive a reboot and a Defender reset.
  #>
  param([Parameter(Mandatory=$true)][string[]]$Paths)

  Write-Step "Antivirus exclusions"

  $viaCmdlet = 0
  $viaPolicy = 0

  $cmd = Get-Command Add-MpPreference -ErrorAction SilentlyContinue
  if ($cmd) {
    foreach ($path in $Paths) {
      try {
        Add-MpPreference -ExclusionPath $path -ErrorAction Stop
        $viaCmdlet++
      } catch {
        Write-Verbose "Add-MpPreference failed for '$path': $($_.Exception.Message)"
      }
    }
  }

  if ($viaCmdlet -eq 0) {
    Write-Info "Add-MpPreference unavailable or failing; using the policy registry instead."
  }

  # Value name is the path itself; the data is ignored by Defender.
  $policyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"
  try {
    New-Item -Path $policyKey -Force | Out-Null
    foreach ($path in $Paths) {
      New-ItemProperty -Path $policyKey -Name $path -Value 0 -PropertyType DWord -Force | Out-Null
      $viaPolicy++
    }
  } catch {
    Write-Warn "Could not write exclusion policy: $($_.Exception.Message)"
  }

  foreach ($path in $Paths) {
    Write-Ok "Excluded: $path"
  }

  if ($viaCmdlet -eq 0 -and $viaPolicy -gt 0) {
    Write-Warn "Policy exclusions can need a reboot before Defender honours them."
    Write-Warn "If a download is still blocked as 'a virus or potentially unwanted"
    Write-Warn "software', reboot and re-run this script."
  }

  Write-Warn "Exclusions reduce protection. They are appropriate inside a"
  Write-Warn "disposable analysis VM and nowhere else."
}


function Disable-DefenderRealtime {
  <#
    Turn off real-time protection through Group Policy.

    Separate from -AddExclusions and opt-in, because it is a much bigger hammer:
    exclusions narrow what Defender inspects, this stops it inspecting anything.

    Policy keys rather than Set-MpPreference for the same reason as above, and
    rather than the Windows Security toggle because that toggle re-enables itself
    on a timer -- which is how a quarantined FakeNet comes back after you thought
    you had turned protection off.

    DisableAntiSpyware is deliberately not set here: current Windows 11 builds
    ignore it, and setting it invites the conclusion that protection is off when
    it is not.
  #>
  Write-Step "Defender real-time protection"

  $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
  $values = @(
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "DisableOnAccessProtection",
    "DisableScanOnRealtimeEnable"
  )

  try {
    New-Item -Path $key -Force | Out-Null
    foreach ($name in $values) {
      Set-ItemProperty -Path $key -Name $name -Value 1 -Type DWord
    }
    Write-Ok "Real-time protection disabled by policy."
    Write-Warn "Reboot for this to take effect. Afterwards the Windows Security"
    Write-Warn "toggle should read 'managed by your administrator', which is the"
    Write-Warn "sign it will stay off rather than flipping back on."
  } catch {
    Write-Warn "Could not write real-time protection policy: $($_.Exception.Message)"
    Write-Warn "Turn it off in Windows Security manually: Virus & threat protection"
    Write-Warn "-> Manage settings. Turn Tamper Protection off first, or nothing sticks."
  }
}

function Invoke-Preflight {
  param([Parameter(Mandatory=$true)][string]$RepoRoot)

  Write-Step "Verifying with the workbench preflight checks"

  $python = Get-Command python -ErrorAction SilentlyContinue
  if (-not $python) {
    Write-Warn "python not found in PATH; skipping verification."
    Write-Warn "Open the Dynamic Analysis window to see tool availability instead."
    return
  }

  $verifier = Join-Path $env:TEMP ("rf_preflight_" + [Guid]::NewGuid().ToString("N") + ".py")

  $lines = @(
    "import sys",
    ("sys.path.insert(0, r'" + $RepoRoot + "')"),
    "from dynamic_analysis.sysmon_collector import sysmon_status",
    "from dynamic_analysis.network_capture import capture_status",
    "from dynamic_analysis.fakenet_runner import fakenet_status",
    "from dynamic_analysis.memory_dump import memory_dump_status",
    "from dynamic_analysis.memory_yara import memory_yara_status",
    "checks = [('Sysmon', sysmon_status()), ('Packet capture', capture_status()), ('Simulated internet', fakenet_status()), ('Process memory', memory_dump_status()), ('Memory YARA', memory_yara_status())]",
    "ready = 0",
    "for name, status in checks:",
    "    ok = bool(status.get('available'))",
    "    ready += 1 if ok else 0",
    "    print(('  [OK]   ' if ok else '  [--]   ') + name)",
    "    note = status.get('note', '')",
    "    if note:",
    "        print('         ' + note)",
    "print()",
    "print('%d of %d telemetry sources ready.' % (ready, len(checks)))",
    "sys.exit(0 if ready == len(checks) else 2)"
  )

  Set-Content -LiteralPath $verifier -Value $lines -Encoding utf8

  try {
    & $python.Source $verifier
    $code = $LASTEXITCODE
    if ($code -eq 0) {
      Write-Ok "All telemetry sources are ready."
    } else {
      Write-Warn "Some sources are not ready. See the notes above."
    }
  } finally {
    Remove-Item -LiteralPath $verifier -Force -ErrorAction SilentlyContinue
  }
}

try {
  $scriptDir = Get-ScriptDir
  $repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
  $toolsDir = Join-Path $repoRoot "tools"

  Write-Info "Repo root: $repoRoot"
  Write-Info "Tools dir: $toolsDir"

  if (-not (Test-Admin)) {
    throw "Administrator rights are required. Sysmon, Npcap and FakeNet-NG all install drivers."
  }

  $vmEvidence = @(Get-VirtualMachineEvidence)
  if ($vmEvidence.Count -eq 0) {
    Write-Host ""
    Write-Warn "This does not look like a virtual machine."
    Write-Warn "These tools install kernel drivers and a system-wide traffic diverter,"
    Write-Warn "and this workbench is used to detonate malware. Installing them on a"
    Write-Warn "physical workstation is strongly discouraged."
    Write-Warn ""
    Write-Warn "If this IS a VM, its identity strings may be spoofed to defeat anti-VM"
    Write-Warn "evasion, which also defeats this check. Re-run with -Force."
    if (-not $Force) {
      throw "Refusing to continue outside a VM. Re-run with -Force only if you are certain."
    }
    Write-Warn "-Force supplied; continuing anyway."
  } else {
    Write-Ok ("Virtual machine detected ({0})." -f $vmEvidence[0])
    foreach ($item in ($vmEvidence | Select-Object -Skip 1)) {
      Write-Verbose "  also: $item"
    }
  }

  New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

  $tempDir = Join-Path $env:TEMP ("rf_tools_" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

  # Exclude the tools directory before downloading, or antivirus quarantines
  # FakeNet-NG the moment it lands on disk.
  if ($DisableRealtimeProtection) {
    Disable-DefenderRealtime
  }

  if ($AddExclusions) {
    # The temp directory matters as much as tools/. Downloads land there first,
    # and Defender scans the file as it is written -- so excluding only the
    # destination leaves the very file that gets blocked unprotected. FakeNet's
    # zip was refused mid-download for exactly this reason.
    Add-DefenderExclusions -Paths @($toolsDir, $tempDir, $env:TEMP)
  } else {
    Write-Warn "Antivirus exclusions not requested. If FakeNet-NG disappears after"
    Write-Warn "download, re-run with -AddExclusions."
  }

  if (-not $SkipSysmon)    { Install-Sysmon -ToolsDir $toolsDir -TempDir $tempDir -ConfigUrl $SysmonConfigUrl }
  else                     { Write-Step "Sysmon"; Write-Warn "Skipped by request." }

  if (-not $SkipWireshark) { Install-Wireshark -TempDir $tempDir }
  else                     { Write-Step "Wireshark / Npcap"; Write-Warn "Skipped by request." }

  if (-not $SkipFakeNet)   { Install-FakeNet -ToolsDir $toolsDir -TempDir $tempDir -Repo $FakeNetRepo }
  else                     { Write-Step "FakeNet-NG"; Write-Warn "Skipped by request." }

  if (-not $SkipProcDump)  { Install-ProcDump -ToolsDir $toolsDir -TempDir $tempDir }
  else                     { Write-Step "ProcDump"; Write-Warn "Skipped by request." }

  # Paired with the dump watcher rather than optional alongside it: the watcher
  # cannot capture a process that lives less time than the gap between its
  # offsets, and a crash dump is taken at exactly that moment.
  if (-not $SkipProcDump)  { Enable-CrashDumps -DumpFolder $CrashDumpFolder }

  if (-not $SkipUpx)       { Install-Upx -ToolsDir $toolsDir -TempDir $tempDir -Repo $UpxRepo }
  else                     { Write-Step "UPX"; Write-Warn "Skipped by request." }

  if (-not $SkipCapa)      { Install-Capa -ToolsDir $toolsDir -TempDir $tempDir -Repo $CapaRepo }
  else                     { Write-Step "capa"; Write-Warn "Skipped by request." }

  if (-not $SkipScriptBlockLogging) { Enable-ScriptBlockLogging }
  else { Write-Step "PowerShell ScriptBlock logging"; Write-Warn "Skipped by request." }

  Invoke-Preflight -RepoRoot $repoRoot

  if (-not $KeepTemp) {
    Remove-Item -Recurse -Force -LiteralPath $tempDir -ErrorAction SilentlyContinue
  } else {
    Write-Warn "Keeping temp folder: $tempDir"
  }

  Write-Host ""
  Write-Ok "Done."
  Write-Info "Take a VM snapshot now, so you can revert to this tooled baseline between detonations."
}
catch {
  Write-Host ""
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.ScriptStackTrace) {
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
  }
  exit 1
}
