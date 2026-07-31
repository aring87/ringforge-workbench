<#
.SYNOPSIS
  Takes and restores analysis-VM snapshots, from the host.

.DESCRIPTION
  Runs on the HOST, alongside vm_net.ps1. VBoxManage exists only here, and a
  guest cannot revert itself.

  Reverting between detonations is not housekeeping, it is what makes a result
  mean anything. Without it, run N inherits whatever run N-1 installed, wrote or
  hooked, and the second sample's report quietly describes both of them. That is
  tolerable for one careful run at a time and fatal for a campaign, which is why
  this exists before the MalwareBazaar work rather than after it.

  Three things here are deliberate and worth knowing.

  The VM is always powered off HARD, never gracefully. A graceful shutdown asks
  the guest to run its shutdown path, and on a machine that has just detonated
  malware that is a request the sample can act on -- shutdown handlers, cleanup
  routines, anti-forensics. Pulling the virtual power cable gives it nothing.

  Containment is re-established BEFORE the VM boots, not after. A snapshot
  restores the network configuration it was captured with, so a baseline taken
  while armed comes back armed. Disarming a stopped VM edits the saved config,
  so the machine never runs in an armed state at all. Restoring is also the one
  moment when the previous run's containment guarantees no longer apply.

  Restoring DISCARDS everything in the guest since the snapshot, including the
  case directory of the run you just did. Export reports first. The confirmation
  prompt exists for that reason and -Force skips it.

.PARAMETER List
  Show snapshots and which one the VM is currently on.

.PARAMETER Take
  Take a snapshot with this name. The VM is powered off first, so the snapshot
  is a clean disk state rather than a captured live memory image.

.PARAMETER Restore
  Restore this snapshot by name.

.PARAMETER Baseline
  Restore -BaselineName. The between-detonations shorthand.

.PARAMETER BaselineName
  Name of the tooled baseline snapshot. Default: "tooling-baseline".

.PARAMETER Delete
  Delete a snapshot by name.

.PARAMETER NoStart
  Do not start the VM after restoring.

.PARAMETER KeepNetworkState
  Do not force the internet-facing adapter off after restoring. Only use this
  when you are deliberately restoring a snapshot in order to go online.

.PARAMETER WaitSeconds
  How long to wait for the guest to come up after starting. Default 180.

.PARAMETER GuestAddress
  Host-only address to ping as a readiness check when Guest Additions are not
  reporting. Default: auto-detected, then skipped.

.PARAMETER Headless
  Start the VM without a window.

.PARAMETER Force
  Skip the confirmation prompt on destructive operations.

.EXAMPLE
  .\scripts\vm_snapshot.ps1 -List

.EXAMPLE
  .\scripts\vm_snapshot.ps1 -Take "tooling-baseline"
  Capture the tooled, hygiened, contained VM once, after bootstrap_tools.ps1.

.EXAMPLE
  .\scripts\vm_snapshot.ps1 -Baseline -Force
  Revert to that baseline between samples, contained and booted, no prompt.
#>

[CmdletBinding()]
param(
  [switch]$List,
  [string]$Take = "",
  [string]$Restore = "",
  [switch]$Baseline,
  [string]$BaselineName = "tooling-baseline",
  [string]$Delete = "",
  [string]$Description = "",
  [switch]$NoStart,
  [switch]$KeepNetworkState,
  [int]$WaitSeconds = 180,
  [string]$GuestAddress = "",
  [switch]$Headless,
  [switch]$Force,
  [string]$VMName = "Windows 11",
  [string]$VBoxManagePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Danger($msg) { Write-Host "[!] $msg" -ForegroundColor Red }
function Write-Step($msg) { Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Magenta }

function Get-ScriptDir {
  if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }
  $inv = $MyInvocation.MyCommand.Path
  if ($inv -and $inv.Trim().Length -gt 0) { return (Split-Path -Parent $inv) }
  return (Get-Location).Path
}

function Test-RunningInGuest {
  # Same guard as vm_net.ps1: the repo is cloned on both sides, and "VBoxManage
  # not found" is a misleading answer to the real mistake.
  $guestServices = @("VBoxService", "VBoxGuest", "VMTools", "VMwareTools", "qemu-ga")
  foreach ($name in $guestServices) {
    if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue)) { return $true }
  }
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    return (("{0} {1}" -f $cs.Manufacturer, $cs.Model) -match 'VirtualBox|VMware|QEMU|Xen|innotek')
  } catch {
    return $false
  }
}

function Find-VBoxManage {
  param([string]$Configured)

  if ($Configured -and (Test-Path -LiteralPath $Configured)) { return $Configured }

  $candidates = @(
    "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }

  $cmd = Get-Command VBoxManage -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  throw "VBoxManage.exe not found. Pass -VBoxManagePath explicitly."
}

function Get-VmRunState {
  param([string]$Exe, [string]$Name)

  $info = & $Exe showvminfo $Name --machinereadable 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Could not read VM '$Name'. Check the name with: VBoxManage list vms"
  }
  foreach ($line in $info) {
    if ([string]$line -match '^VMState="(.+)"$') { return $matches[1] }
  }
  return "unknown"
}

function Get-Snapshots {
  param([string]$Exe, [string]$Name)

  $output = & $Exe snapshot $Name list --machinereadable 2>&1
  if ($LASTEXITCODE -ne 0) {
    # VBoxManage exits non-zero when a VM simply has no snapshots yet, which is
    # a normal state rather than an error worth aborting on.
    return [PSCustomObject]@{ Names = @(); Current = "" }
  }

  $names = @()
  $current = ""
  foreach ($line in $output) {
    $text = [string]$line
    if ($text -match '^CurrentSnapshotName="(.+)"$') {
      $current = $matches[1]
    } elseif ($text -match '^SnapshotName(?:-[\d-]+)?="(.+)"$') {
      $names += $matches[1]
    }
  }
  return [PSCustomObject]@{ Names = $names; Current = $current }
}

function Stop-VmHard {
  param([string]$Exe, [string]$Name)

  $state = Get-VmRunState -Exe $Exe -Name $Name
  if ($state -match 'poweroff|aborted') {
    Write-Info "VM is already stopped ($state)."
    return
  }

  # Hard, always. See the note at the top: asking a machine that has just run
  # malware to shut itself down politely hands the sample one last execution
  # opportunity, at the exact moment nobody is watching.
  Write-Info "Powering off (hard)..."
  & $Exe controlvm $Name poweroff 2>&1 | Out-Null

  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 700
    $state = Get-VmRunState -Exe $Exe -Name $Name
    if ($state -match 'poweroff|aborted') {
      Write-Ok "Stopped."
      return
    }
  }
  throw "VM '$Name' did not stop within 60 seconds (state: $state)."
}

function Get-GuestIPv4 {
  param([string]$Exe, [string]$Name)

  # Guest Additions publish this when present. The analysis VM is debloated, so
  # treat its absence as normal rather than as a fault.
  foreach ($index in 0..3) {
    $prop = "/VirtualBox/GuestInfo/Net/$index/V4/IP"
    $out = & $Exe guestproperty get $Name $prop 2>&1
    if ($LASTEXITCODE -eq 0 -and ([string]$out) -match 'Value:\s*(\d{1,3}(?:\.\d{1,3}){3})') {
      $ip = $matches[1]
      # The host-only address is the one reachable while disarmed.
      if ($ip -notmatch '^(0\.|169\.254\.)') { return $ip }
    }
  }
  return ""
}

function Wait-GuestReady {
  param([string]$Exe, [string]$Name, [int]$Seconds, [string]$Address)

  Write-Info "Waiting up to $Seconds seconds for the guest to come up..."
  $deadline = (Get-Date).AddSeconds($Seconds)

  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3

    $state = Get-VmRunState -Exe $Exe -Name $Name
    if ($state -notmatch 'running') { continue }

    # Preferred signal: Guest Additions reporting a logged-in session.
    $out = & $Exe guestproperty get $Name "/VirtualBox/GuestInfo/OS/LoggedInUsers" 2>&1
    if ($LASTEXITCODE -eq 0 -and ([string]$out) -match 'Value:\s*(\d+)' -and [int]$matches[1] -ge 1) {
      Write-Ok "Guest reports a logged-in session."
      return $true
    }

    if (-not $Address) { $Address = Get-GuestIPv4 -Exe $Exe -Name $Name }
    if ($Address -and (Test-Connection -ComputerName $Address -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
      Write-Ok "Guest is responding on $Address."
      return $true
    }
  }

  # Not fatal. Without Guest Additions there may be no readiness signal at all,
  # and reporting that honestly beats either hanging or claiming success.
  Write-Warn "No readiness signal within $Seconds seconds."
  Write-Warn "The VM may still be booting. Check it before detonating."
  return $false
}

function Confirm-Destructive {
  param([string]$Message)

  if ($Force) { return $true }
  Write-Host ""
  Write-Danger $Message
  $answer = Read-Host "Type 'yes' to continue"
  return ($answer -eq "yes")
}

function Set-Containment {
  param([string]$Name)

  # Delegates to vm_net.ps1 rather than reimplementing adapter detection, so
  # containment has exactly one definition. It now handles a stopped VM, which
  # is what lets this run before the machine boots.
  $vmNet = Join-Path (Get-ScriptDir) "vm_net.ps1"
  if (-not (Test-Path -LiteralPath $vmNet)) {
    Write-Warn "vm_net.ps1 not found; cannot verify containment automatically."
    return
  }
  & $vmNet -Disarm -VMName $Name
}

try {
  if (Test-RunningInGuest) {
    throw ("This script runs on the HOST, not inside the analysis VM. " +
           "A guest cannot revert itself, and VBoxManage exists only on the host.")
  }

  # Wrapped in @(): a pipeline that matches nothing yields $null and one that
  # matches a single item yields a scalar, and under Set-StrictMode neither has
  # a .Count to read.
  $modes = @(@([bool]$List, [bool]$Take, [bool]$Restore, [bool]$Baseline, [bool]$Delete) |
             Where-Object { $_ })
  if ($modes.Count -eq 0) { $List = $true }
  if ($modes.Count -gt 1) {
    throw "Choose one of -List, -Take, -Restore, -Baseline or -Delete."
  }

  $exe = Find-VBoxManage -Configured $VBoxManagePath
  $snapshots = Get-Snapshots -Exe $exe -Name $VMName

  # ---------------------------------------------------------------- list ---
  if ($List) {
    Write-Host ""
    Write-Info "VM: $VMName  (state: $(Get-VmRunState -Exe $exe -Name $VMName))"
    if ($snapshots.Names.Count -eq 0) {
      Write-Warn "No snapshots. Take one after bootstrap_tools.ps1 with:"
      Write-Warn "  .\scripts\vm_snapshot.ps1 -Take '$BaselineName'"
      exit 0
    }
    Write-Host ""
    foreach ($name in $snapshots.Names) {
      if ($name -eq $snapshots.Current) {
        Write-Ok ("  * {0}   (current)" -f $name)
      } else {
        Write-Host ("    {0}" -f $name) -ForegroundColor Gray
      }
    }
    Write-Host ""
    if ($snapshots.Names -contains $BaselineName) {
      Write-Ok "Baseline '$BaselineName' is present; -Baseline will revert to it."
    } else {
      Write-Warn "No snapshot named '$BaselineName'. -Baseline will not work until one exists."
    }
    exit 0
  }

  # ---------------------------------------------------------------- take ---
  if ($Take) {
    if ($snapshots.Names -contains $Take) {
      throw "A snapshot named '$Take' already exists. Delete it first, or pick another name."
    }

    Write-Step "Taking snapshot '$Take'"
    # Powered off first: a snapshot of a running VM captures live memory too,
    # which is larger, slower to restore, and restores the machine mid-session
    # rather than to a clean boot.
    Stop-VmHard -Exe $exe -Name $VMName

    # Not $args: that is an automatic variable in PowerShell and assigning to it
    # inside a script is asking for trouble.
    $takeArgs = @("snapshot", $VMName, "take", $Take)
    if ($Description) { $takeArgs += @("--description", $Description) }
    & $exe @takeArgs
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage failed to take the snapshot." }

    Write-Ok "Snapshot '$Take' taken."
    exit 0
  }

  # -------------------------------------------------------------- delete ---
  if ($Delete) {
    if ($snapshots.Names -notcontains $Delete) {
      throw "No snapshot named '$Delete'. Run -List to see what exists."
    }
    if (-not (Confirm-Destructive "This deletes snapshot '$Delete' from '$VMName'.")) {
      Write-Warn "Cancelled."
      exit 1
    }
    & $exe snapshot $VMName delete $Delete
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage failed to delete the snapshot." }
    Write-Ok "Snapshot '$Delete' deleted."
    exit 0
  }

  # ------------------------------------------------------------- restore ---
  $target = if ($Baseline) { $BaselineName } else { $Restore }

  if ($snapshots.Names -notcontains $target) {
    throw ("No snapshot named '$target'. Run -List to see what exists, " +
           "or take one with -Take '$target'.")
  }

  Write-Step "Restoring '$target' on '$VMName'"
  if (-not (Confirm-Destructive ("Restoring DISCARDS everything in the guest since that snapshot, " +
                                 "including the case directory of the last run. Export reports first."))) {
    Write-Warn "Cancelled."
    exit 1
  }

  Stop-VmHard -Exe $exe -Name $VMName

  & $exe snapshot $VMName restore $target
  if ($LASTEXITCODE -ne 0) { throw "VBoxManage failed to restore '$target'." }
  Write-Ok "Restored to '$target'."

  # Before starting, never after. A snapshot restores the cable state it was
  # captured with, so this is what stops a baseline taken while armed from
  # booting armed.
  if (-not $KeepNetworkState) {
    Write-Step "Re-establishing containment"
    Set-Containment -Name $VMName
  } else {
    Write-Warn "-KeepNetworkState given: the restored adapter state is whatever the snapshot held."
    Write-Warn "Check it with .\scripts\vm_net.ps1 before detonating."
  }

  if ($NoStart) {
    Write-Host ""
    Write-Ok "Done. VM left powered off."
    exit 0
  }

  Write-Step "Starting"
  $type = if ($Headless) { "headless" } else { "gui" }
  & $exe startvm $VMName --type $type
  if ($LASTEXITCODE -ne 0) { throw "VBoxManage failed to start '$VMName'." }

  $ready = Wait-GuestReady -Exe $exe -Name $VMName -Seconds $WaitSeconds -Address $GuestAddress

  Write-Host ""
  Write-Ok "Reverted to '$target' and started."
  if (-not $KeepNetworkState) {
    Write-Ok "Contained: the internet-facing adapter was disconnected before boot."
  }
  if (-not $ready) {
    Write-Warn "Readiness was not confirmed; verify the guest is up before detonating."
  }
  Write-Host ""
  Write-Info "Confirm containment in the run summary's network_isolation.level, not the GUI line."
}
catch {
  Write-Host ""
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.ScriptStackTrace) {
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
  }
  exit 1
}
