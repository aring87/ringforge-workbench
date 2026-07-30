<#
.SYNOPSIS
  Installs the tier-1 dynamic analysis telemetry tools into an analysis VM.

.DESCRIPTION
  Sets up the tools that close the gaps Procmon cannot see:

    Sysmon        process injection, image loads, WMI persistence, DNS queries
    Wireshark     dumpcap + tshark, and the Npcap driver, for full packet capture
    FakeNet-NG    a simulated internet so samples proceed through their real logic
    ProcDump      process memory images, for scanning what a packer unpacked

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
  is a well-tested general-purpose baseline.

.PARAMETER AddExclusions
  Add a Windows Defender exclusion for the tools directory before downloading.
  FakeNet-NG is reliably flagged as a HackTool and is otherwise quarantined on
  arrival. Appropriate inside a disposable analysis VM and nowhere else.

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
  [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
  [string]$FakeNetRepo = "mandiant/flare-fakenet-ng",
  [switch]$AddExclusions,
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
  param([Parameter(Mandatory=$true)][string[]]$Paths)

  Write-Step "Antivirus exclusions"

  $cmd = Get-Command Add-MpPreference -ErrorAction SilentlyContinue
  if (-not $cmd) {
    Write-Warn "Add-MpPreference unavailable; skipping (Defender may not be present)."
    return
  }

  foreach ($path in $Paths) {
    try {
      Add-MpPreference -ExclusionPath $path -ErrorAction Stop
      Write-Ok "Excluded: $path"
    } catch {
      Write-Warn "Could not exclude '$path': $($_.Exception.Message)"
    }
  }

  Write-Warn "Exclusions reduce protection. They are appropriate inside a"
  Write-Warn "disposable analysis VM and nowhere else."
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
  if ($AddExclusions) {
    Add-DefenderExclusions -Paths @($toolsDir)
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
