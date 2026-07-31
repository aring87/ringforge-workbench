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

.PARAMETER DisableEDR
  Disable Defender for Endpoint (the Sense services) and DiagTrack. Opt-in,
  because it is a bigger step than silencing an updater -- but an EDR agent
  uploads suspicious samples to its tenant and can quarantine them before they
  run, so it has to go before real samples. Without this switch the agents are
  reported and left alone. A Wazuh agent is only ever reported, since that is
  usually the analyst's own SIEM.

.PARAMETER EnableAutoLogon
  Log the guest in automatically at boot, so a snapshot revert produces a usable
  machine without anyone touching it. Opt-in, and it stores the account password
  in the registry in PLAINTEXT -- readable by anything running in the guest,
  samples included. Only appropriate for a disposable, isolated VM whose
  password is used nowhere else.

.PARAMETER AutoLogonUser
  Account to log on automatically. Defaults to the current user.

.PARAMETER AutoLogonPassword
  That account's password. Prompted for if omitted; stored in plaintext either
  way.

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
  [switch]$DisableEDR,
  [switch]$EnableAutoLogon,
  [string]$AutoLogonUser = "",
  [string]$AutoLogonPassword = "",
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

#: EDR agents. Reported always, disabled only with -DisableEDR.
#:
#: An EDR agent on an analysis VM is not merely noisy. Defender for Endpoint
#: uploads suspicious samples to whichever tenant it reports to, so detonating
#: real malware on an enrolled machine submits that sample and raises alerts
#: under the owner's account. It can also quarantine independently of the
#: Defender antivirus settings, which are a different mechanism with different
#: controls.
#:
#: SenseNdr appeared in the FakeNet process list of every run until it was dealt
#: with -- a permanent, invisible contribution to every result.
$EDR_PATTERNS = @(
  @{ Label = "Defender for Endpoint"; Pattern = '^Sense' },
  @{ Label = "Connected User Experiences"; Pattern = '^DiagTrack$' }
)

#: Reported but never touched: this one is usually the analyst's own SIEM
#: shipping to a host-only address, which is a deliberate part of the lab.
$EDR_REPORT_ONLY = @(
  @{ Label = "Wazuh agent"; Pattern = 'Wazuh' }
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
        # A dry run cannot discover an access denial without attempting the
        # write, so groups known to be OS-owned are called out rather than
        # counted. Otherwise the preview promises ten changes and the real run
        # makes two, which makes the summary worth less than no summary.
        if ($group.ContainsKey("Protected")) {
          Write-Skip "likely protected by the OS: $($task.Path)"
          $protected++
        } else {
          # "attempt", not "disable". Ownership is per task, not per group --
          # \WindowsUpdate\Scheduled Start yields while Refresh Group Policy
          # Cache beside it does not -- and the only way to find out is to try.
          Write-Host "    would attempt: $($task.Path)" -ForegroundColor Yellow
          $changed++
        }
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

  $already = $false
  try {
    $current = Get-ItemProperty -Path $key -Name NoAutoUpdate -ErrorAction Stop
    $already = ($current.NoAutoUpdate -eq 1)
  } catch { }

  if ($already) {
    Write-Ok "NoAutoUpdate=1 already set."
  } elseif ($DryRun) {
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


function Invoke-EdrAgents {
  <#
    Report EDR agents, and disable them when -DisableEDR is given.

    Sense is a protected-process service, so sc.exe is commonly denied even
    elevated; Set-ServiceDisabled's registry fallback is what actually lands it.
    Tamper Protection has to be off first, the same as for Defender itself.

    Disabling is not offboarding. The machine stays registered in whatever tenant
    it was enrolled with and simply reports as inactive. For a lab VM that is
    fine; if the enrolment is not yours to remove, use the offboarding package
    from the Defender portal instead.
  #>
  Write-Step "EDR agents"

  $services = @(Get-Service -ErrorAction SilentlyContinue)
  $found = 0
  $changed = 0

  foreach ($group in $EDR_PATTERNS) {
    $matched = @($services | Where-Object { $_.Name -match $group.Pattern })
    if ($matched.Count -eq 0) {
      Write-Skip "$($group.Label): not present"
      continue
    }

    $found += $matched.Count

    foreach ($service in $matched) {
      if ($service.StartType -eq "Disabled") {
        Write-Skip "already disabled: $($service.Name)"
        continue
      }

      if (-not $DisableEDR) {
        Write-Danger ("{0}: {1} is {2}/{3}" -f $group.Label, $service.Name, $service.Status, $service.StartType)
        continue
      }

      if ($DryRun) {
        Write-Host "    would disable: $($service.Name)" -ForegroundColor Yellow
        $changed++
        continue
      }

      if (Set-ServiceDisabled -Name $service.Name) {
        $changed++
        Write-Ok "disabled: $($service.Name)"
      } elseif ($service.Name -eq "Sense") {
        # Not a misconfiguration, and not fixable locally. Defender for Endpoint
        # enforces its own tamper protection from the tenant, independently of
        # the Windows Security toggle, and Sense runs as a protected process.
        # Both sc.exe and the registry are refused even to an administrator --
        # which is the product working correctly: an EDR a local admin could
        # switch off would be trivially defeated by anything running as admin.
        Write-Warn "could not disable: Sense -- blocked by Defender for Endpoint's own"
        Write-Warn "tamper protection, which is managed from the tenant and is separate"
        Write-Warn "from the Windows Security toggle. Turning that toggle off does not"
        Write-Warn "release it."
        Write-Warn "Offboard from the Defender portal instead: Settings -> Endpoints ->"
        Write-Warn "Offboarding, then run the package it gives you and reboot."
        Write-Warn ""
        Write-Warn "No portal access -- an expired trial tenant, say -- means Safe Mode,"
        Write-Warn "where the service is not running to defend itself. Boot with"
        Write-Warn "'bcdedit /set {current} safeboot minimal', then:"
        Write-Warn '  reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v Start /t REG_DWORD /d 4 /f'
        Write-Warn '  reg add "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection" /v OnboardingState /t REG_DWORD /d 0 /f'
        Write-Warn "then 'bcdedit /deletevalue {current} safeboot' and reboot. Clearing"
        Write-Warn "OnboardingState matters as much as the service: left set, Sense keeps"
        Write-Warn "trying to reach a tenant that is no longer listening."
      } else {
        Write-Warn "could not disable: $($service.Name) (protected service)"
      }
    }
  }

  foreach ($group in $EDR_REPORT_ONLY) {
    foreach ($service in @($services | Where-Object { $_.Name -match $group.Pattern })) {
      Write-Info ("{0}: {1} is {2}/{3} -- left alone, this is usually your own SIEM." -f
                  $group.Label, $service.Name, $service.Status, $service.StartType)
    }
  }

  if ($found -gt 0 -and -not $DisableEDR) {
    Write-Warn ""
    Write-Warn "An EDR agent uploads suspicious samples to its tenant and can quarantine"
    Write-Warn "them before they run. Re-run with -DisableEDR, or offboard properly from"
    Write-Warn "the portal, before detonating anything real."
  }

  if ($changed -gt 0) {
    Write-Warn "Reboot for this to take full effect."
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


function Enable-AutoLogon {
  <#
    Logs the guest in automatically after a revert.

    Without this, `vm_snapshot.ps1 -Baseline` leaves a machine sitting at the
    login screen: reachable, contained, and unable to run anything. Between
    samples that is a manual step in a loop meant to be repeated dozens of
    times, and it is the only one that cannot be scripted from the host.

    The password is stored in the registry in PLAINTEXT. That is how
    AutoAdminLogon works, and it means anything running in the guest can read
    it -- including the samples. Acceptable only because this VM is disposable,
    isolated and reverted between runs, and only if the password is not used
    anywhere else. Sysinternals Autologon.exe stores it as an LSA secret
    instead, which is marginally better but still readable by anything running
    elevated, so it is not the meaningful protection it appears to be.
  #>
  param([string]$User, [string]$Password)

  Write-Step "Automatic logon"

  if (-not $User) { $User = $env:USERNAME }
  if (-not $Password) {
    Write-Warn "No -AutoLogonPassword given; prompting."
    Write-Warn "It is written to the registry in plaintext either way."
    $Password = Read-Host "Password for $User"
  }

  $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

  Write-Danger "The password will be stored in plaintext at:"
  Write-Danger "  $key\DefaultPassword"
  Write-Danger "Anything running in this guest can read it, samples included."

  if ($DryRun) {
    Write-Skip "Dry run: would set AutoAdminLogon=1, DefaultUserName=$User for $env:COMPUTERNAME."
    return
  }

  try {
    Set-ItemProperty -Path $key -Name "AutoAdminLogon" -Value "1" -Type String
    Set-ItemProperty -Path $key -Name "DefaultUserName" -Value $User -Type String
    Set-ItemProperty -Path $key -Name "DefaultDomainName" -Value $env:COMPUTERNAME -Type String
    Set-ItemProperty -Path $key -Name "DefaultPassword" -Value $Password -Type String

    # Windows decrements AutoLogonCount on each automatic logon and stops once
    # it reaches zero. If anything ever set it, autologin would work a fixed
    # number of times and then quietly stop -- which after a revert looks
    # exactly like the setting never applied.
    if ($null -ne (Get-ItemProperty -Path $key -Name "AutoLogonCount" -ErrorAction SilentlyContinue)) {
      Remove-ItemProperty -Path $key -Name "AutoLogonCount" -ErrorAction SilentlyContinue
      Write-Info "Removed AutoLogonCount, which would have expired the setting."
    }

    Write-Ok "Automatic logon enabled for $User."
    Write-Info "Re-take the baseline snapshot so reverts keep this."
  } catch {
    Write-Warn "Could not enable automatic logon: $($_.Exception.Message)"
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
  Invoke-EdrAgents
  Show-DefenderState
  Show-OptionalSoftware

  if ($EnableAutoLogon) {
    Enable-AutoLogon -User $AutoLogonUser -Password $AutoLogonPassword
  }

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
