<#
.SYNOPSIS
  Boots the analysis VM to a sign-in screen, waits for the capture to prove
  itself, and only then drives the logon that starts the payload.

.DESCRIPTION
  Runs on the HOST, alongside vm_snapshot.ps1 and vm_net.ps1.

  This exists because the first logon-capture run lost a race it could not win.
  The capture was an ONSTART scheduled task chosen on the reasoning that it
  "runs before any user session exists". Measured 31 Aug: the sample's ONLOGON
  payload started 21:32:55 and the capture started 21:36:46. Task Scheduler
  delays and throttles boot-triggered tasks. ONSTART is earlier than ONLOGON;
  it is not early.

  Nothing about the trigger fixes that, so the race is removed instead. With
  AutoAdminLogon at 0 the guest boots to the sign-in screen and stops. No logon
  session is created, so no ONLOGON task fires -- the sample's included. The
  capture starts whenever Task Scheduler gets round to it, confirms its own
  backing file is growing, and sets a guest property. This script waits for
  that property and then types the credentials. The payload starts inside a
  capture already known to be running.

  The capture being late stops mattering. What replaces it is a number that can
  be checked afterwards: the payload's start minus the capture's ready, which
  is positive by construction or the run is void.

  Three things here are deliberate.

  THE READINESS PROPERTY IS DELETED BEFORE THE VM STARTS. Guest properties
  survive a reboot. A stale readiness from a previous boot would be read as
  this boot's, the credentials would go into a machine with no capture running,
  and the run would look perfect while proving nothing. The guest also sets it
  TRANSIENT, so both ends of that trap are closed.

  THE SIGNAL MEANS "THE BACKING FILE IS GROWING", NOT "PROCMON WAS LAUNCHED".
  Launching was the thing that was true last time while nothing was being
  captured, because Procmon was sitting on a modal dialog. The guest confirms
  256 MB of preallocated backing file before it signals.

  THE PASSWORD REACHES VBoxManage ON A COMMAND LINE, so it is briefly visible
  to anything enumerating host processes. That is consistent with this bench's
  existing threat model and no worse: AutoAdminLogon already stores the same
  password in plaintext in the guest's registry, where any sample can read it,
  and vm_hygiene.ps1 says so when it writes it. It is still a host exposure and
  is named here rather than left to be discovered.

  WHAT IS NOT PROVEN, and must not be assumed twice: nobody has yet watched
  Procmon capture successfully from session 0. The first attempt died on two
  modals, both of which are now cleared before launch, but "the modals were the
  only problem" is a hypothesis of exactly the shape that cost the last run.
  Use -ProveChannel on the clean baseline first. If session 0 turns out to be a
  wall, the gate still holds -- a second local account lets Procmon run
  interactively in an operator session while the target user's logon, and only
  that logon, fires the payload.

.PARAMETER Vm
  VM name or UUID. Default: RingForge-Analysis.

.PARAMETER Snapshot
  Restore this snapshot before starting, by delegating to vm_snapshot.ps1 so
  containment is re-established the same way it is for every other restore.
  Omit to start the VM as it stands.

.PARAMETER Password
  The account's password, as a SecureString. Prompted for if omitted. Not
  needed with -ProveChannel.

.PARAMETER User
  Type this user name before the password, for a sign-in screen that does not
  already have the account selected. Omit on a single-account guest.

.PARAMETER TimeoutSeconds
  How long to wait for the capture's signal. Default 900. The failed run's
  capture started 231 seconds after boot and a cold boot from snapshot has
  measured 182 seconds, so a tight timeout reports a failure that is really
  impatience.

.PARAMETER ProveChannel
  Wait for the signal, report how long it took, and stop without typing
  anything. This is the measurement to take before a malware run: it proves the
  guest can reach the host from session 0 and that the capture verifies itself,
  on a machine where nothing is at stake.

.PARAMETER DryRun
  Print what would be done. Starts nothing, types nothing.

.PARAMETER Headless
  Start the VM without a window. Not recommended for the first runs: the
  sign-in screen is the only direct evidence that the gate did what it says.

.EXAMPLE
  .\scripts\vm_gated_logon.ps1 -Snapshot tooling-baseline -ProveChannel
  Prove the channel and the self-verification on a clean guest, first.

.EXAMPLE
  .\scripts\vm_gated_logon.ps1 -Snapshot ce0d08be-installed-onlogon-armed
  The real run. Prompts for the password, waits for the capture, logs on.

.NOTES
  Guest side, before the snapshot is taken:

    .venv\Scripts\python.exe scripts\logon_capture.py --arm --gate-logon ^
        --out C:\logon-capture --procmon C:\...\tools\rf_trace64.exe --window 600

  Afterwards, the two numbers that decide whether the run counts:

    logon_capture.json   ready_seconds_after_boot
    sysmon_boot.json     payload.seconds_after_boot

  The second must be larger than the first. If it is not, the capture did not
  precede the payload and the run says nothing about the payload's first
  seconds, whatever it recorded.
#>

[CmdletBinding()]
param(
  [string]$Vm = "RingForge-Analysis",
  [string]$Snapshot = "",
  [securestring]$Password,
  [string]$User = "",
  [int]$TimeoutSeconds = 900,
  [int]$PollSeconds = 2,
  [string]$ReadyProperty = "/RingForge/CaptureReady",
  [string]$OutFile = "",
  [switch]$ProveChannel,
  [switch]$Headless,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Danger($msg) { Write-Host "[!] $msg" -ForegroundColor Red }
function Write-Step($msg) { Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Magenta }


function Find-VBoxManage {
  <#
    The PATH entry is not reliable on this bench, so the install location is
    checked first and the PATH is the fallback rather than the other way round.
  #>
  $candidates = @(
    "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe",
    "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
  )
  foreach ($candidate in $candidates) {
    if (Test-Path $candidate) { return $candidate }
  }
  $onPath = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
  if ($onPath) { return $onPath.Source }
  throw "VBoxManage.exe not found. This script runs on the host, not in the guest."
}


function Invoke-VBox {
  <#
    Returns stdout and the exit code rather than throwing, because several
    calls here are expected to fail routinely -- deleting a property that does
    not exist is the normal case, not an error.
  #>
  param([string[]]$Arguments, [switch]$Quiet)

  if (-not $Quiet) { Write-Verbose ("VBoxManage " + ($Arguments -join " ")) }
  $stdout = & $script:VBoxManage @Arguments 2>&1
  return [pscustomobject]@{
    ExitCode = $LASTEXITCODE
    Output   = ($stdout | Out-String).Trim()
    Ok       = ($LASTEXITCODE -eq 0)
  }
}


function Get-VmState {
  $result = Invoke-VBox @("showvminfo", $Vm, "--machinereadable") -Quiet
  if (-not $result.Ok) { throw "No such VM: $Vm" }
  foreach ($line in $result.Output -split "`r?`n") {
    if ($line -match '^VMState="([^"]+)"') { return $Matches[1] }
  }
  return "unknown"
}


function Clear-ReadyProperty {
  <#
    The stale-readiness trap. Guest properties outlive a reboot, so a value
    left by the previous boot reads as this boot's readiness -- and the
    credentials would go into a machine with no capture running.
  #>
  $existing = Invoke-VBox @("guestproperty", "get", $Vm, $ReadyProperty) -Quiet
  if ($existing.Output -notmatch "No value set") {
    Write-Warn "A readiness value was already set: $($existing.Output)"
    Write-Info "Deleting it. It belongs to a previous boot, not this one."
  }
  if ($DryRun) { Write-Info "Dry run: would delete $ReadyProperty"; return }
  Invoke-VBox @("guestproperty", "delete", $Vm, $ReadyProperty) -Quiet | Out-Null
}


function Get-ReadyValue {
  $result = Invoke-VBox @("guestproperty", "get", $Vm, $ReadyProperty) -Quiet
  if (-not $result.Ok) { return "" }
  if ($result.Output -match "^Value:\s*(.+)$") { return $Matches[1].Trim() }
  return ""
}


function Wait-ForCapture {
  <#
    Polls rather than using `guestproperty wait`, which blocks on the next
    CHANGE. If the guest signals between the VM starting and the wait being
    issued -- unlikely here, but the failure is a hang with no output -- a wait
    never returns. A poll cannot miss a value that is already there.
  #>
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $started = Get-Date
  Write-Info "Waiting up to $TimeoutSeconds s for $ReadyProperty ..."

  while ((Get-Date) -lt $deadline) {
    $value = Get-ReadyValue
    if ($value) {
      $elapsed = [int]((Get-Date) - $started).TotalSeconds
      Write-Ok "Capture signalled after $elapsed s: $value"
      return [pscustomobject]@{ Value = $value; ElapsedSeconds = $elapsed }
    }
    $state = Get-VmState
    if ($state -ne "running") {
      throw "The VM left the running state ($state) before the capture signalled."
    }
    Start-Sleep -Seconds $PollSeconds
  }

  throw @"
No readiness signal within $TimeoutSeconds s.

The capture did not confirm a growing backing file, so nothing here will type
anything -- typing now would start the payload into a machine that may not be
recording. Read C:\logon-capture\logon_capture.json in the guest: it says which
stage it reached and why. The usual causes are a Procmon modal that cannot be
answered from session 0, and VBoxControl.exe missing so the signal could not be
sent at all.
"@
}


function Send-Logon {
  <#
    Scancodes for the framing keys, keyboardputstring for the password itself.

    The sign-in screen needs a keypress to lift the lock-screen curtain before
    the password box exists at all, which is why the space comes first and why
    there is a pause after it: typing into a curtain that has not lifted sends
    the password nowhere and the run fails silently at the last step.
  #>
  param([string]$PlainPassword)

  # space, then release
  Write-Info "Lifting the lock screen."
  if (-not $DryRun) {
    Invoke-VBox @("controlvm", $Vm, "keyboardputscancode", "39", "b9") | Out-Null
    Start-Sleep -Seconds 3
  }

  if ($User) {
    Write-Info "Typing the user name."
    if (-not $DryRun) {
      Invoke-VBox @("controlvm", $Vm, "keyboardputstring", $User) | Out-Null
      # tab, then release
      Invoke-VBox @("controlvm", $Vm, "keyboardputscancode", "0f", "8f") | Out-Null
      Start-Sleep -Seconds 1
    }
  }

  Write-Info "Typing the password."
  if ($DryRun) {
    Write-Info "Dry run: would send the password and Enter."
    return (Get-Date).ToUniversalTime()
  }

  Invoke-VBox @("controlvm", $Vm, "keyboardputstring", $PlainPassword) | Out-Null
  Start-Sleep -Milliseconds 500
  # enter, then release
  Invoke-VBox @("controlvm", $Vm, "keyboardputscancode", "1c", "9c") | Out-Null
  return (Get-Date).ToUniversalTime()
}


# ---------------------------------------------------------------------------

$script:VBoxManage = Find-VBoxManage
Write-Info "VBoxManage: $script:VBoxManage"

$state = Get-VmState
Write-Info "$Vm is $state"

if ($state -eq "running" -and $Snapshot) {
  throw "$Vm is running. Restoring a snapshot means powering it off first; do that deliberately with vm_snapshot.ps1."
}

if (-not $ProveChannel -and -not $DryRun -and -not $Password) {
  $Password = Read-Host "Password for the guest account" -AsSecureString
}

Write-Step "Clearing the previous boot's readiness"
Clear-ReadyProperty

if ($Snapshot) {
  Write-Step "Restoring $Snapshot"
  $snapshotScript = Join-Path (Split-Path -Parent $PSCommandPath) "vm_snapshot.ps1"
  if (-not (Test-Path $snapshotScript)) { throw "vm_snapshot.ps1 not found next to this script." }
  if ($DryRun) {
    Write-Info "Dry run: would run vm_snapshot.ps1 -Restore $Snapshot -NoStart -Force"
  } else {
    # Delegated rather than reimplemented: that script settles the VM state,
    # re-establishes containment before the machine boots, and warns about an
    # open Manager window. All three matter more here than a shorter call.
    & $snapshotScript -Restore $Snapshot -NoStart -Force
    if ($LASTEXITCODE -ne 0) { throw "vm_snapshot.ps1 failed to restore $Snapshot." }
  }
}

if ((Get-VmState) -ne "running") {
  Write-Step "Starting $Vm"
  $type = if ($Headless) { "headless" } else { "gui" }
  if ($DryRun) {
    Write-Info "Dry run: would start $Vm ($type)"
  } else {
    $start = Invoke-VBox @("startvm", $Vm, "--type", $type)
    if (-not $start.Ok) { throw "Could not start ${Vm}: $($start.Output)" }
  }
}

$bootAt = (Get-Date).ToUniversalTime()

if ($DryRun) {
  Write-Step "Dry run complete"
  Write-Info "Nothing was started, waited for or typed."
  return
}

Write-Step "Waiting for the capture"
$ready = Wait-ForCapture

# The guest sends "1|<seconds after boot>|<local timestamp>".
$readyFields = $ready.Value -split '\|'
$readyAfterBoot = if ($readyFields.Count -ge 2) { $readyFields[1] } else { "" }
if ($readyAfterBoot) {
  Write-Info "The capture was ready $readyAfterBoot s after the guest booted."
}

if ($ProveChannel) {
  Write-Step "Channel proven"
  Write-Ok "The guest reached the host from session 0 and the capture verified itself."
  Write-Info "Nothing was typed. Log on by hand if you want to watch what follows."
  return
}

Write-Step "Driving the logon"
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
)
try {
  $typedAt = Send-Logon -PlainPassword $plain
} finally {
  # Not a security boundary -- it was on a command line a moment ago -- but
  # there is no reason to leave it in this session's memory either.
  $plain = $null
  [GC]::Collect()
}

Write-Ok "Credentials sent at $($typedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')) (host UTC)."

$record = [ordered]@{
  vm                  = $Vm
  snapshot            = $Snapshot
  ready_property      = $ReadyProperty
  ready_value         = $ready.Value
  ready_after_boot_s  = $readyAfterBoot
  waited_seconds      = $ready.ElapsedSeconds
  started_at_utc      = $bootAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
  logon_sent_at_utc   = $typedAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
  user_typed          = [bool]$User
}

if (-not $OutFile) {
  $OutFile = Join-Path (Get-Location) "gated_logon.json"
}
$record | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding utf8
Write-Ok "Wrote $OutFile"

Write-Step "What to check when the window closes"
Write-Host @"
If the sign-in did not take -- a mistyped character, a curtain that had not
lifted -- the guest is sitting at the sign-in screen and no payload ran. The
capture will still write a manifest and a CSV of a machine doing nothing, which
is not a failed run so much as an empty one. Look at the VM window.

Two numbers decide whether the run counts:

  logon_capture.json   ready_seconds_after_boot   ($readyAfterBoot s this run)
  sysmon_boot.json     payload.seconds_after_boot

The second must be LARGER than the first. That is the whole point of the gate,
and it is the claim the last run could not make.

  .venv\Scripts\python.exe scripts\sysmon_since_boot.py --out C:\logon-capture --image <payload.exe>
  .venv\Scripts\python.exe scripts\logon_capture.py --analyse --out C:\logon-capture --image <payload.exe>
"@
