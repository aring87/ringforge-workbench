<#
.SYNOPSIS
  Quiets the background software churn in an analysis VM, so a detonation's
  diffs describe the sample and not Windows.

.DESCRIPTION
  Runs in the GUEST, elevated. Its job is to make the before/after snapshots a
  dynamic run takes -- scheduled tasks, services, autoruns -- stable between
  identical runs.

  This is not cosmetic. A Chrome update that landed mid-detonation was reported
  as two suspicious new autoruns entries and pushed a benign sample's score from
  19 to 29. Whatever a real sample changes has to be distinguishable from what
  the machine was going to do anyway.

  What it disables, and why each needs a different mechanism:

    Browser/app updaters   Chrome, Edge, Acrobat and OneDrive updater tasks and
                           services. Task names carry version numbers and GUIDs
                           and several live in subfolders, so they are matched by
                           path pattern rather than by name.

    MDM enrolment          dmwappushservice and the EnterpriseMgmt tasks. A VM
                           cloned from a managed desktop retries OMA-DM
                           enrolment forever, and each attempt writes into the
                           scheduled-task store -- which the persistence check
                           correctly reports as task-store writes that had
                           nothing to do with the sample.

    Windows Update scans   The InstallService scan tasks plus the NoAutoUpdate
                           policy. The UpdateOrchestrator tasks are owned by
                           TrustedInstaller and cannot be disabled by an
                           administrator; they are reported and skipped rather
                           than treated as failures.

    Delivery Optimization  DoSvc, which refuses sc.exe config on some builds and
                           needs its start type written directly to the registry.

  wuauserv is deliberately left alone. Windows restores its start type, so
  disabling it does not hold; the policy key removes its reason to run instead,
  which is what actually stops the churn.

  Defender is reported, not changed. Turning protection off is a bigger decision
  than disabling an updater, and it belongs to whoever runs this -- but it does
  have to happen before real samples, because Defender will quarantine the
  sample the same way it quarantined FakeNet-NG. Use
  bootstrap_tools.ps1 -DisableRealtimeProtection for that.

  Nothing here is reverted by this script. The intended workflow is to run it
  once, verify, and snapshot -- then revert to that snapshot between samples.

.PARAMETER DryRun
  Report what would change without changing anything.

.PARAMETER SkipWindowsUpdate
  Leave Windows Update scanning and its policy alone.

.PARAMETER Force
  Proceed even when this does not look like a virtual machine. Required on a VM
  whose identity strings are spoofed for anti-VM hardening.

.EXAMPLE
  .\scripts\vm_hygiene.ps1 -DryRun
  Show what is currently noisy, change nothing.

.EXAMPLE
  .\scripts\vm_hygiene.ps1
  Apply, then print a verification pass.
#>

[CmdletBinding()]
param(
  [switch]$DryRun,
  [switch]$SkipWindowsUpdate,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg)   { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)     { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)   { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Danger($msg) { Write-Host "[!] $msg" -ForegroundColor Red }
function Write-Step($msg)   { Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Magenta }
function Write-Skip($msg)   { Write-Host "    $msg" -ForegroundColor DarkGray }

#: Scheduled tasks to disable, matched against the task's full path.
#:
#: Patterns, not names. The real names carry version numbers and GUIDs --
#: GoogleUpdaterTaskSystem152.0.7933.0{6C04...} -- and live in subfolders, so an
#: exact-name list silently matches nothing and reports success.
$TASK_PATTERNS = @(
  @{ Label = "Google updater and helpers";  Pattern = 'Google' },
  @{ Label = "Edge updater";                Pattern = 'Edge.*Update' },
  @{ Label = "Acrobat updater";             Pattern = 'Acrobat.*Update' },
  @{ Label = "OneDrive updater";            Pattern = 'OneDrive.*Update' },
  # MDM/OMA-DM enrolment. On a VM cloned from a managed desktop this retries
  # forever, and each attempt writes a task file under \Tasks\Microsoft\Windows\
  # EnterpriseMgmt\ -- which the persistence check correctly reads as a write
  # into the task store, producing three persistence "hits" per run that have
  # nothing to do with the sample.
  @{ Label = "MDM enrolment (OMA-DM)";      Pattern = 'EnterpriseMgmt' },
  @{ Label = "Windows Update scans";        Pattern = '\\InstallService\\';      WindowsUpdate = $true },
  @{ Label = "Windows Update scheduling";   Pattern = '\\WindowsUpdate\\';       WindowsUpdate = $true },
  @{ Label = "Update Orchestrator";         Pattern = '\\UpdateOrchestrator\\';  WindowsUpdate = $true; Protected = $true }
)

#: Services to disable, matched by name.
#:
#: wuauserv is absent on purpose: Windows restores its start type, so disabling
#: it does not stick. It is handled by policy instead.
$SERVICE_PATTERNS = @(
  @{ Label = "Google updater services";   Pattern = 'GoogleUpdater|^gupdate' },
  @{ Label = "Chrome elevation service";  Pattern = 'GoogleChromeElevationService' },
  @{ Label = "Edge updater services";     Pattern = '^edgeupdate' },
  @{ Label = "Edge elevation service";    Pattern = 'MicrosoftEdgeElevationService' },
  @{ Label = "Delivery Optimization";     Pattern = '^DoSvc$' },
  # Drives the OMA-DM retries above. Disabling the tasks alone is not enough:
  # this service creates fresh ones per enrolment session.
  @{ Label = "MDM push (OMA-DM)";         Pattern = '^dmwappushservice$' },
  # Microsoft Account sign-in. Its SharePoint lookups showed up as Sysmon DNS
  # queries during a run. Self-heals to Manual like wuauserv, but with OneDrive
  # gone it has nothing left to wake it.
  @{ Label = "MS Account sign-in";        Pattern = '^wlidsvc$' },
  @{ Label = "Update Session Orchestr.";  Pattern = '^UsoSvc$'; WindowsUpdate = $true }
)

#: Software an analysis VM does not need. Reported only -- uninstalling is the
#: analyst's call, and a disabled updater is enough to stop the churn.
$OPTIONAL_SOFTWARE = @(
  @{ Name = "Google Chrome";  Paths = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                                        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") },
  @{ Name = "Adobe Acrobat";  Paths = @("$env:ProgramFiles\Adobe",
                                        "${env:ProgramFiles(x86)}\Adobe") },
  @{ Name = "OneDrive";       Paths = @("$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
                                        "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe") }
)


function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Test-LooksLikeVirtualMachine {
  <#
    Deliberately a short check. bootstrap_tools.ps1 has the exhaustive version;
    this one only has to be good enough to refuse on a real workstation, and
    -Force is the escape hatch for a hardened VM whose DMI strings are spoofed.

    Guest-additions services and driver files are checked first because they
    survive that spoofing, which the identity strings do not.
  #>
  foreach ($name in @("VBoxService", "VBoxGuest", "VMTools", "VMwareTools", "qemu-ga")) {
    if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue)) { return $true }
  }

  $driverDir = Join-Path $env:SystemRoot "System32\drivers"
  foreach ($driver in @("VBoxGuest.sys", "VBoxSF.sys", "vmhgfs.sys", "vm3dmp.sys")) {
    if (Test-Path -LiteralPath (Join-Path $driverDir $driver)) { return $true }
  }

  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if (("{0} {1}" -f $cs.Manufacturer, $cs.Model) -match 'VirtualBox|VMware|QEMU|Xen|innotek|Parallels') {
      return $true
    }
  } catch { }

  return $false
}


function Get-AllScheduledTasks {
  <#
    Every registered task, walked through the Task Scheduler COM API.

    Get-ScheduledTask is not usable here. Debloated Windows images -- the usual
    base for an analysis VM -- are missing the
    Root\Microsoft\Windows\TaskScheduler CIM namespace, and the cmdlet fails with
    "Invalid namespace". The COM service does not depend on it.

    GetTasks(1) includes hidden tasks; GetFolders(0) is the documented no-flags
    call. Most updater tasks are hidden, so omitting the flag misses them.
  #>
  $service = New-Object -ComObject Schedule.Service
  $service.Connect()

  $results = New-Object System.Collections.ArrayList

  function Walk-Folder($folder) {
    foreach ($task in $folder.GetTasks(1)) { [void]$results.Add($task) }
    foreach ($child in $folder.GetFolders(0)) { Walk-Folder $child }
  }

  Walk-Folder $service.GetFolder('\')
  return $results
}


function Disable-NoisyTasks {
  param([Parameter(Mandatory=$true)][object[]]$Tasks)

  Write-Step "Scheduled tasks"

  $changed = 0
  $already = 0
  $protected = 0

  foreach ($group in $TASK_PATTERNS) {
    if ($SkipWindowsUpdate -and $group.ContainsKey("WindowsUpdate")) {
      Write-Skip "$($group.Label): skipped by -SkipWindowsUpdate"
      continue
    }

    $matched = @($Tasks | Where-Object { $_.Path -match $group.Pattern })
    if ($matched.Count -eq 0) {
      Write-Skip "$($group.Label): none present"
      continue
    }

    Write-Info "$($group.Label): $($matched.Count) task(s)"

    foreach ($task in $matched) {
      if (-not $task.Enabled) {
        $already++
        Write-Skip "already disabled: $($task.Path)"
        continue
      }

      if ($DryRun) {
        Write-Host "    would disable: $($task.Path)" -ForegroundColor Yellow
        $changed++
        continue
      }

      try {
        $task.Enabled = $false
        $changed++
        Write-Ok "disabled: $($task.Path)"
      } catch {
        # UpdateOrchestrator tasks are owned by TrustedInstaller, so an
        # administrator cannot disable them. Expected, not a failure: taking
        # ownership to force it can break servicing, and the NoAutoUpdate policy
        # removes their reason to run anyway.
        $protected++
        Write-Skip "protected by the OS, left alone: $($task.Path)"
      }
    }
  }

  return @{ Changed = $changed; Already = $already; Protected = $protected }
}


function Set-ServiceDisabled {
  <#
    Disable one service, returning $true when its start type ends up Disabled.

    sc.exe rather than Set-Service: the argument really is "start= disabled",
    with the space after the equals sign, and sc.exe reports a usable error where
    Set-Service on a protected service does not.

    Note this is sc.exe explicitly. In PowerShell, "sc" is an alias for
    Set-Content and would silently do something entirely unrelated.
  #>
  param([Parameter(Mandatory=$true)][string]$Name)

  $null = & sc.exe config "$Name" start= disabled 2>&1
  $null = & sc.exe stop "$Name" 2>&1   # 1062 "not started" is fine and ignored

  $state = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($null -ne $state -and $state.StartType -eq "Disabled") { return $true }

  # DoSvc refuses sc.exe config on some builds with access denied even when
  # elevated. Writing the start type directly works where the service control
  # manager call does not. 4 = disabled.
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
  try {
    Set-ItemProperty -Path $key -Name Start -Value 4 -Type DWord -ErrorAction Stop
  } catch {
    return $false
  }

  $state = Get-Service -Name $Name -ErrorAction SilentlyContinue
  return ($null -ne $state -and $state.StartType -eq "Disabled")
}


function Disable-NoisyServices {
  Write-Step "Services"

  $changed = 0
  $already = 0
  $failed = 0

  $services = @(Get-Service -ErrorAction SilentlyContinue)

  foreach ($group in $SERVICE_PATTERNS) {
    if ($SkipWindowsUpdate -and $group.ContainsKey("WindowsUpdate")) {
      Write-Skip "$($group.Label): skipped by -SkipWindowsUpdate"
      continue
    }

    $matched = @($services | Where-Object { $_.Name -match $group.Pattern })
    if ($matched.Count -eq 0) {
      Write-Skip "$($group.Label): none present"
      continue
    }

    foreach ($service in $matched) {
      if ($service.StartType -eq "Disabled") {
        $already++
        Write-Skip "already disabled: $($service.Name)"
        continue
      }

      if ($DryRun) {
        Write-Host "    would disable: $($service.Name) (currently $($service.StartType))" -ForegroundColor Yellow
        $changed++
        continue
      }

      if (Set-ServiceDisabled -Name $service.Name) {
        $changed++
        Write-Ok "disabled: $($service.Name)"
      } else {
        $failed++
        Write-Warn "could not disable: $($service.Name)"
      }
    }
  }

  return @{ Changed = $changed; Already = $already; Failed = $failed }
}


function Set-WindowsUpdatePolicy {
  Write-Step "Windows Update policy"

  if ($SkipWindowsUpdate) {
    Write-Skip "skipped by -SkipWindowsUpdate"
    return
  }

  $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

  if ($DryRun) {
    Write-Host "    would set NoAutoUpdate=1 at $key" -ForegroundColor Yellow
  } else {
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name NoAutoUpdate -Value 1 -Type DWord
    Write-Ok "NoAutoUpdate=1"
  }

  # Reported rather than changed. Windows restores this service's start type, so
  # disabling it does not hold; with no scan tasks and NoAutoUpdate set it has no
  # trigger, and an idle service produces no diff.
  $wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
  if ($null -ne $wu) {
    Write-Info "wuauserv is $($wu.Status)/$($wu.StartType) -- left as-is, deliberately."
    Write-Skip "Windows resets its start type; the policy above is what stops the scanning."
  }
}


function Show-DefenderState {
    <#
      Report Defender's posture and say what to do about it.

      Reported rather than changed, because turning protection off is a bigger
      decision than disabling an updater and belongs to whoever is running this.
      bootstrap_tools.ps1 -DisableRealtimeProtection does the change.

      Get-MpComputerStatus is unavailable here -- the Defender WMI namespace is
      missing on debloated images -- so state is read from the policy keys and
      the process list instead.

      Worth being blunt about why this matters: Defender quarantined fakenet.exe
      mid-session and then refused to let it be downloaded again, and its
      MpCmdRun scan added 80,000 file events to one run and none to the next.
      With a real sample it will quarantine the sample itself.
    #>
  Write-Step "Defender"

  $rtKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
  $exKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"

  $rtDisabled = $false
  try {
    $value = Get-ItemProperty -Path $rtKey -Name DisableRealtimeMonitoring -ErrorAction Stop
    $rtDisabled = ($value.DisableRealtimeMonitoring -eq 1)
  } catch { }

  $exclusions = @()
  try { $exclusions = @((Get-Item $exKey -ErrorAction Stop).Property) } catch { }

  $engine = Get-Process MsMpEng -ErrorAction SilentlyContinue

  if ($rtDisabled) {
    Write-Ok "Real-time protection is disabled by policy."
  } else {
    Write-Danger "Real-time protection is NOT disabled by policy."
    Write-Warn "The Windows Security toggle alone re-enables itself on a timer."
    Write-Warn "Fix it with:  .\scripts\bootstrap_tools.ps1 -AddExclusions -DisableRealtimeProtection"
    Write-Warn "then reboot. Turn Tamper Protection off first in Windows Security,"
    Write-Warn "or the policy will not apply."
  }

  if ($exclusions.Count -gt 0) {
    Write-Ok ("{0} path exclusion(s) set by policy." -f $exclusions.Count)
    foreach ($path in $exclusions) { Write-Skip $path }
  } else {
    Write-Warn "No policy path exclusions. The tools and temp directories should be"
    Write-Warn "excluded, or FakeNet-NG gets quarantined on download."
  }

  if ($engine) {
    # Expected, and not itself a problem: the service runs regardless.
    Write-Skip "MsMpEng is running, which is normal even with real-time protection off."
  }
}


function Show-OptionalSoftware {
  Write-Step "Software this VM does not need"

  $found = @()
  foreach ($item in $OPTIONAL_SOFTWARE) {
    foreach ($path in $item.Paths) {
      if ($path -and (Test-Path -LiteralPath $path)) {
        $found += $item.Name
        break
      }
    }
  }

  if ($found.Count -eq 0) {
    Write-Ok "None of the usual desktop software is installed."
    return
  }

  Write-Warn ("Installed: {0}" -f ($found -join ", "))
  Write-Skip "Their updaters are disabled above, which stops the churn."
  Write-Skip "Uninstalling is more durable: an update reinstates services under new"
  Write-Skip "version-suffixed names, which this script would then have to be re-run to catch."

  if ($found -contains "OneDrive") {
    Write-Danger "OneDrive syncs local files to cloud storage. On a machine that"
    Write-Danger "detonates malware and writes memory dumps, that is an exfiltration"
    Write-Danger "path as much as a noise source. Removing it is strongly advised."
  }
}


function Show-Verification {
  <#
    Re-reads state rather than trusting the change tally, and reports only what
    is still enabled. "Nothing listed" is the pass condition.
  #>
  Write-Step "Verification"

  $tasks = Get-AllScheduledTasks
  $patterns = @($TASK_PATTERNS | Where-Object { -not $_.ContainsKey("Protected") })

  $stillEnabled = @()
  foreach ($group in $patterns) {
    if ($SkipWindowsUpdate -and $group.ContainsKey("WindowsUpdate")) { continue }
    $stillEnabled += @($tasks | Where-Object { $_.Path -match $group.Pattern -and $_.Enabled })
  }

  if ($stillEnabled.Count -eq 0) {
    Write-Ok "No targeted scheduled task is still enabled."
  } else {
    Write-Warn "Still enabled after the pass:"
    foreach ($task in $stillEnabled) { Write-Host "    $($task.Path)" -ForegroundColor Yellow }
  }

  $services = @(Get-Service -ErrorAction SilentlyContinue)
  $stillOn = @()
  foreach ($group in $SERVICE_PATTERNS) {
    if ($SkipWindowsUpdate -and $group.ContainsKey("WindowsUpdate")) { continue }
    $stillOn += @($services | Where-Object { $_.Name -match $group.Pattern -and $_.StartType -ne "Disabled" })
  }

  if ($stillOn.Count -eq 0) {
    Write-Ok "Every targeted service is disabled."
  } else {
    Write-Warn "Not disabled:"
    foreach ($service in $stillOn) {
      Write-Host "    $($service.Name) ($($service.Status)/$($service.StartType))" -ForegroundColor Yellow
    }
  }
}


try {
  Write-Host ""
  Write-Info "RingForge analysis VM hygiene"
  if ($DryRun) { Write-Warn "Dry run: nothing will be changed." }

  if (-not (Test-Admin)) {
    throw "Administrator rights are required to change services and scheduled tasks."
  }

  if (-not (Test-LooksLikeVirtualMachine)) {
    Write-Host ""
    Write-Danger "This does not look like a virtual machine."
    Write-Danger "This script disables Windows Update scanning, Delivery Optimization,"
    Write-Danger "and browser update services. On a real workstation that leaves the"
    Write-Danger "machine unpatched."
    Write-Warn ""
    Write-Warn "If this IS the analysis VM, its identity strings may be spoofed to"
    Write-Warn "defeat anti-VM evasion, which also defeats this check. Re-run with -Force."
    if (-not $Force) {
      throw "Refusing to continue outside a VM. Re-run with -Force only if you are certain."
    }
    Write-Warn "-Force supplied; continuing anyway."
  } else {
    Write-Ok "Virtual machine detected."
  }

  $tasks = Get-AllScheduledTasks
  Write-Info "$($tasks.Count) scheduled tasks registered."

  $taskResult = Disable-NoisyTasks -Tasks $tasks
  $serviceResult = Disable-NoisyServices
  Set-WindowsUpdatePolicy
  Show-DefenderState
  Show-OptionalSoftware

  if (-not $DryRun) {
    Show-Verification
  }

  Write-Step "Summary"
  Write-Host ("  tasks    : {0} changed, {1} already disabled, {2} protected by the OS" -f
              $taskResult.Changed, $taskResult.Already, $taskResult.Protected)
  Write-Host ("  services : {0} changed, {1} already disabled, {2} could not be changed" -f
              $serviceResult.Changed, $serviceResult.Already, $serviceResult.Failed)

  Write-Host ""
  if ($DryRun) {
    Write-Warn "Dry run complete. Re-run without -DryRun to apply."
  } else {
    Write-Ok "Done."
    Write-Host ""
    Write-Info "Next, in order:"
    Write-Host "  1. Reboot the guest, then re-run this script with -DryRun." -ForegroundColor Gray
    Write-Host "     It should report nothing left to change. Anything that reappears is" -ForegroundColor Gray
    Write-Host "     being reinstated by its own updater, and wants uninstalling instead." -ForegroundColor Gray
    Write-Host "  2. Detonate test_specs\memory_canary\canary.ps1 twice, back to back." -ForegroundColor Gray
    Write-Host "     Both runs should report autoruns_diff_summary.new_entries = 0." -ForegroundColor Gray
    Write-Host "     That is the real measure: identical input, identical diffs." -ForegroundColor Gray
    Write-Host "  3. Snapshot, and revert to it between samples." -ForegroundColor Gray
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
