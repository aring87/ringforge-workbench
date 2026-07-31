<#
.SYNOPSIS
  Connects or disconnects an analysis VM's internet-facing adapter, from the host.

.DESCRIPTION
  Runs on the HOST, not inside the analysis VM. (bootstrap_tools.ps1 is the
  guest-side script; this is its counterpart.)

  Toggling the virtual cable from the hypervisor is what makes containment
  enforceable. An adapter disabled inside the guest can be re-enabled by
  anything running there with administrator rights, including the sample.
  VBoxManage is outside the guest's reach.

  The VM does not need to be shut down: link state changes take effect
  immediately on a running VM.

  By default the internet-facing adapter is detected by its attachment type
  (NAT or Bridged) rather than assumed to be NIC 1, so a rebuilt VM with a
  different adapter order cannot cause the host-only adapter to be
  disconnected instead -- a mistake that would leave the VM connected while
  appearing to have been contained.

.PARAMETER Arm
  Connect the internet-facing adapter. For updates and git pull.
  Do not detonate anything in this state.

.PARAMETER Disarm
  Disconnect the internet-facing adapter, leaving host-only intact.
  This is the state to detonate in.

.PARAMETER VMName
  Virtual machine name. Default: "Windows 11".

.PARAMETER Nic
  Adapter number to act on. Default 0 auto-detects the NAT/Bridged adapter.

.EXAMPLE
  .\scripts\vm_net.ps1
  Show the current state of every adapter.

.EXAMPLE
  .\scripts\vm_net.ps1 -Disarm
  Contain the VM before detonating a sample.
#>

[CmdletBinding()]
param(
  [switch]$Arm,
  [switch]$Disarm,
  [string]$VMName = "Windows 11",
  [int]$Nic = 0,
  [string]$VBoxManagePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Danger($msg) { Write-Host "[!] $msg" -ForegroundColor Red }

function Test-RunningInGuest {
  <#
    True when this looks like the analysis VM rather than the host.

    The repository is cloned in both places, so it is easy to run this script
    in the guest, where VBoxManage does not exist and "not found" is a
    misleading answer to the real mistake.
  #>
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

function Get-VmState {
  param([string]$Exe, [string]$Name)

  $info = & $Exe showvminfo $Name 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Could not read VM '$Name'. Check the name with: VBoxManage list vms"
  }

  $state = "unknown"
  $adapters = @()

  foreach ($line in $info) {
    $text = [string]$line

    if ($text -match '^State:\s+(.+?)\s*(\(|$)') {
      $state = $matches[1].Trim()
    }

    # "NIC 1:  MAC: ..., Attachment: NAT, Cable connected: off, ..."
    if ($text -match '^NIC (\d+):\s+MAC: (\S+?),\s+Attachment: (.+?),\s+Cable connected: (\w+)') {
      # Capture every group up front. Any further -match resets the automatic
      # $matches variable, so reading it after another comparison yields null.
      $nicNumber = [int]$matches[1]
      $attachment = $matches[3].Trim()
      $cable = $matches[4].Trim().ToLower()

      $adapters += [PSCustomObject]@{
        Nic        = $nicNumber
        Attachment = $attachment
        Cable      = $cable
        External   = ($attachment -match 'NAT|Bridged')
      }
    }
  }

  return [PSCustomObject]@{ State = $state; Adapters = $adapters }
}

function Show-State {
  param([object]$Vm, [string]$Name)

  Write-Host ""
  Write-Info "VM: $Name  (state: $($Vm.State))"

  if ($Vm.Adapters.Count -eq 0) {
    Write-Warn "No enabled adapters found."
    return
  }

  foreach ($adapter in $Vm.Adapters) {
    $role = if ($adapter.External) { "INTERNET" } else { "internal" }
    $line = ("  NIC {0}  {1,-9} {2,-38} cable: {3}" -f
             $adapter.Nic, $role, $adapter.Attachment, $adapter.Cable)
    if ($adapter.External -and $adapter.Cable -eq "on") {
      Write-Danger $line
    } elseif ($adapter.External) {
      Write-Ok $line
    } else {
      Write-Host $line -ForegroundColor Gray
    }
  }

  $live = @($Vm.Adapters | Where-Object { $_.External -and $_.Cable -eq "on" })
  Write-Host ""
  if ($live.Count -gt 0) {
    Write-Danger "NOT CONTAINED: the VM can reach the internet. Do not detonate."
    Write-Warn   "Contain it with: .\scripts\vm_net.ps1 -Disarm -VMName '$Name'"
  } else {
    Write-Ok "CONTAINED: no internet-facing adapter is connected."
  }
}

try {
  if ($Arm -and $Disarm) {
    throw "Specify only one of -Arm or -Disarm."
  }

  # The repo is cloned on both host and guest, so catch the wrong one early.
  if (Test-RunningInGuest) {
    throw ("This script runs on the HOST, not inside the analysis VM. " +
           "VBoxManage exists only on the host, and toggling the adapter from " +
           "the host is what makes containment enforceable -- the guest can " +
           "re-enable anything it disabled itself. Run it from the host clone.")
  }

  $exe = Find-VBoxManage -Configured $VBoxManagePath
  $vmState = Get-VmState -Exe $exe -Name $VMName

  if (-not ($Arm -or $Disarm)) {
    Show-State -Vm $vmState -Name $VMName
    exit 0
  }

  # Resolve which adapter to act on.
  if ($Nic -gt 0) {
    $target = @($vmState.Adapters | Where-Object { $_.Nic -eq $Nic })
    if ($target.Count -eq 0) { throw "NIC $Nic is not enabled on '$VMName'." }
    $targets = $target
  } else {
    $targets = @($vmState.Adapters | Where-Object { $_.External })
    if ($targets.Count -eq 0) {
      Write-Ok "No NAT or Bridged adapter on '$VMName'; it has no internet path to change."
      Show-State -Vm $vmState -Name $VMName
      exit 0
    }
  }

  # A running VM takes link changes live through controlvm; a stopped one needs
  # modifyvm, which edits the saved configuration instead.
  #
  # Handling the stopped case matters for snapshot restores. A snapshot brings
  # back the cable state it was taken with, so a baseline captured while armed
  # would boot armed. Disarming before the VM starts closes that window
  # entirely, rather than racing to disarm a machine that is already up.
  $isRunning = ($vmState.State -match 'running')
  $desired = if ($Arm) { "on" } else { "off" }

  if (-not $isRunning) {
    Write-Info "VM is $($vmState.State); changing the saved adapter configuration."
  }

  foreach ($adapter in $targets) {
    if ($adapter.Cable -eq $desired) {
      Write-Info "NIC $($adapter.Nic) ($($adapter.Attachment)) is already $desired."
      continue
    }
    Write-Info "Setting NIC $($adapter.Nic) ($($adapter.Attachment)) cable $desired..."
    if ($isRunning) {
      & $exe controlvm $VMName ("setlinkstate{0}" -f $adapter.Nic) $desired
    } else {
      & $exe modifyvm $VMName ("--cableconnected{0}" -f $adapter.Nic) $desired
    }
    if ($LASTEXITCODE -ne 0) {
      throw "VBoxManage failed to set link state on NIC $($adapter.Nic)."
    }
  }

  # Re-read rather than assume the change took.
  Start-Sleep -Milliseconds 500
  $vmState = Get-VmState -Exe $exe -Name $VMName
  Show-State -Vm $vmState -Name $VMName

  if ($Arm) {
    Write-Host ""
    Write-Warn "Internet is enabled for updates. Disarm before detonating anything."
  }
}
catch {
  Write-Host ""
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.ScriptStackTrace) {
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
  }
  exit 1
}
