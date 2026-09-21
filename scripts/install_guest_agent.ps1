<#
.SYNOPSIS
  Registers `guest_run_agent.ps1` as a scheduled task. Runs in the GUEST,
  elevated, once, before the snapshot is taken.

.DESCRIPTION
  The agent has to start on its own after the host boots this machine, and
  there are two ways to arrange that. They are not equivalent and the choice
  changes what the analysis sees.

  **`-OnStart` (default): runs as SYSTEM when the machine boots.**
  No credentials stored anywhere, works with nobody logged on, and is the only
  option for a truly unattended sweep. The cost is real: the sample detonates
  in SYSTEM context, not a user session. Many samples behave differently or
  not at all -- `%APPDATA%` resolves elsewhere, `HKCU` is a different hive, and
  anything that expects a desktop finds none. For *measuring* a corpus that is
  a systematic bias, not a detail.

  **`-OnLogon`: runs as the logged-on user.**
  Faithful: the sample runs where a real one would. It needs somebody to log
  on, which for an unattended sweep means `AutoAdminLogon` -- and that stores
  the account password **in cleartext** in the registry. On a disposable
  analysis guest that is an acceptable trade, and `logon_capture.py`
  deliberately never touches those values so this is left as a decision rather
  than made quietly. Set autologon yourself; this script will not ask for a
  password and does not want one.

  Either way the timing is not to be trusted. Measured 31 Aug: an `ONSTART`
  capture task started **3m51s after** the sample's own `ONLOGON` payload,
  because Task Scheduler delays and throttles boot-triggered tasks. That is
  why the host waits for the agent's `ringforge-ready` file rather than
  assuming a run began because the machine came up.

.PARAMETER OnStart
  Register an ONSTART task running as SYSTEM. The default.

.PARAMETER OnLogon
  Register an ONLOGON task running as the current user instead.

.PARAMETER TaskName
  Defaults to `RingForgeRunAgent`.

.PARAMETER NoSelfUpdate
  Register the task so the agent ignores provisioning drops on the exchange.
  **Use this for a malicious corpus.** The exchange is writable by the guest
  and survives a snapshot restore, so a sample running with administrator
  rights could plant its own `provision-*` directory -- a
  persistence-across-revert path that is reachable on any later boot carrying
  no sample. Read-only-in delivery is the real fix and is not built.

  The switch has existed on `guest_run_agent.ps1` since the self-update was
  added, and docs/HANDOFF.md names it as the mitigation; until now nothing
  could pass it, because the task's argument string was fixed.

  Registering it changes nothing on its own: every run restores the baseline,
  which carries whatever task the snapshot was taken with. Re-run this in the
  guest and take a new snapshot from poweroff.

.PARAMETER Remove
  Unregister the task and exit.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\install_guest_agent.ps1
#>

[CmdletBinding(DefaultParameterSetName = "Install")]
param(
  [Parameter(ParameterSetName = "Install")][switch]$OnStart,
  [Parameter(ParameterSetName = "Install")][switch]$OnLogon,
  [string]$TaskName = "RingForgeRunAgent",
  [string]$AgentPath = "",
  [Parameter(ParameterSetName = "Install")][switch]$NoSelfUpdate,
  [Parameter(ParameterSetName = "Remove")][switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

$elevated = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $elevated) {
  throw ("this needs to run elevated: registering a task that runs as SYSTEM " +
         "requires it, and so do the collectors the agent invokes.")
}

if ($Remove) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Ok "removed '$TaskName' (if it existed)"
  exit 0
}

if (-not $AgentPath) {
  $AgentPath = Join-Path $PSScriptRoot "guest_run_agent.ps1"
}
if (-not (Test-Path -LiteralPath $AgentPath)) {
  throw "the agent is not at '$AgentPath'. Pass -AgentPath."
}
$AgentPath = (Resolve-Path -LiteralPath $AgentPath).Path

# Default to ONSTART unless ONLOGON was asked for, so the unattended case is
# what you get by not thinking about it.
if (-not $OnStart -and -not $OnLogon) { $OnStart = $true }
if ($OnStart -and $OnLogon) {
  throw "pick one of -OnStart or -OnLogon; they place the sample in different contexts"
}

# **`-NoSelfUpdate` had nowhere to be passed from, and that is why this
# parameter exists.** `guest_run_agent.ps1` has taken the switch since the
# self-update was added, and docs/HANDOFF.md names it as *the* mitigation for
# a malicious corpus -- "the exchange is guest-writable and survives a
# restore, so a sample could plant a drop". But this line is the only place in
# the project that builds the agent's arguments, it was a fixed string, and
# nothing else re-registers the task. The flag existed, the documentation
# pointed at it, and no code path could reach it.
#
# **Registering it is not enough on its own.** The baseline snapshot carries
# the task as it was when the snapshot was taken, and every run begins by
# restoring that snapshot -- so changing this script changes nothing until
# somebody re-runs it in the guest and takes a NEW snapshot from poweroff.
# That is the same trap the install itself has: see *Provisioning the guest*.
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$AgentPath`""
if ($NoSelfUpdate) {
  $arguments += " -NoSelfUpdate"
  Write-Warn "self-update is OFF for this task: the guest will ignore provisioning drops"
  Write-Warn "until it is re-registered without -NoSelfUpdate. Appropriate for a"
  Write-Warn "malicious corpus, and it means provisioning becomes a console job again."
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments

# **No boot delay, no random delay, no start-when-available.** Every one of
# those makes Task Scheduler's throttling worse, and the whole reason the host
# waits for a `ready` file is that this trigger cannot be trusted to be prompt.
# Nothing here should make it less prompt on purpose.
$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit ([TimeSpan]::FromHours(4)) `
  -MultipleInstances IgnoreNew

if ($OnStart) {
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest
  $context = "SYSTEM at startup"
  Write-Warn ("the sample will detonate in SYSTEM context, not a user session. " +
              "For corpus fidelity consider -OnLogon plus autologon.")
} else {
  $me = "$env:USERDOMAIN\$env:USERNAME"
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $me
  $principal = New-ScheduledTaskPrincipal -UserId $me `
    -LogonType Interactive -RunLevel Highest
  $context = "$me at logon"
  Write-Warn ("this fires only when somebody logs on. For an unattended sweep " +
              "that means AutoAdminLogon, which stores the password in cleartext " +
              "in the registry. Set it yourself; this script will not.")
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null

Write-Ok "registered '$TaskName' -- $context"
Write-Info "agent: $AgentPath"

$task = Get-ScheduledTask -TaskName $TaskName
Write-Info "state: $($task.State)"
Write-Info ("verify from the host by delivering a sample and watching for " +
            "'ringforge-ready' in <exchange>\current")
