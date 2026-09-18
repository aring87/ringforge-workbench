<#
.SYNOPSIS
  Registers the logon task that continues an interrupted corpus sweep.

.DESCRIPTION
  Runs on the HOST. Installs a Scheduled Task that calls resume_sweep.ps1 at
  logon, which is what makes a four-to-five day corpus survive a restart
  without anybody noticing it stopped. All the judgement lives in
  resume_sweep.ps1; this file only decides when it fires and as whom.

  Three choices worth knowing.

  IT RUNS ONLY WHEN YOU ARE LOGGED ON, as you, interactively. That is not
  laziness about credentials -- it is required. VirtualBox registers VMs per
  user profile and VBoxSVC is a per-user service, so a task running as SYSTEM
  in session 0 would not find the guest this sweep drives. Running as the user
  also means no password is stored anywhere, which is the right posture for a
  bench whose whole design keeps guest credentials off the host.

  IT WAITS TWO MINUTES AFTER LOGON. The exchange, the corpus and the runs
  directory are all on an external drive, and VBoxSVC has to be up. Firing
  into a half-ready machine produces a confusing refusal in the log and a
  corpus that did not restart. resume_sweep.ps1 waits for the volume as well;
  the two together are belt and braces, and neither costs anything.

  NEW INSTANCES ARE IGNORED, NOT QUEUED. If the task somehow fires twice, the
  second one is dropped rather than held to run afterwards. Queueing would
  mean a second controller starting the moment the first finished its checks.
  resume_sweep.ps1 refuses to start a second sweep anyway; this is the outer
  of the two guards.

  The execution time limit is disabled. The launcher exits within seconds of
  detaching the sweep, so the limit should never matter -- but Task Scheduler
  terminates a task's process tree when a limit expires, and the one thing
  worse than a corpus that stopped is a corpus killed at the four-hour mark by
  its own babysitter.

.PARAMETER RunDirectory
  The sweep directory to watch: the one holding manifest.json beside cases/.

.PARAMETER TaskName
  What it is called in Task Scheduler.

.PARAMETER Unregister
  Remove the task. Do this when the corpus finishes -- resume_sweep.ps1 says
  so in its log when it sees a completed run.

.PARAMETER Status
  Show whether it is registered, when it last ran and what it returned.

.PARAMETER RunNow
  Trigger it immediately as a rehearsal. Safe while a sweep is running: the
  launcher finds the live process and declines.

.EXAMPLE
  .\scripts\register_resume_task.ps1 -RunDirectory G:\ringforge-runs\benign-102-v2

.EXAMPLE
  .\scripts\register_resume_task.ps1 -Status

.EXAMPLE
  .\scripts\register_resume_task.ps1 -Unregister
#>
[CmdletBinding()]
param(
    [string]$RunDirectory,
    [string]$TaskName = "RingForge resume sweep",
    [switch]$Unregister,
    [switch]$Status,
    [switch]$RunNow,
    [switch]$StripBomsWhenDone
)

$ErrorActionPreference = "Stop"

$launcher = Join-Path $PSScriptRoot "resume_sweep.ps1"

function Show-Status {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        "not registered: '$TaskName'"
        return
    }
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    "registered : $TaskName"
    "state      : $($task.State)"
    "action     : $($task.Actions[0].Execute) $($task.Actions[0].Arguments)"
    "last run   : $($info.LastRunTime)"
    "last result: 0x{0:X} ({0})" -f $info.LastTaskResult
    "next run   : $($info.NextRunTime)"
}

if ($Status) {
    Show-Status
    exit 0
}

if ($Unregister) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        "nothing to remove: '$TaskName' is not registered"
        exit 0
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    "removed: $TaskName"
    exit 0
}

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName
    "triggered: $TaskName -- read the launcher's log for what it decided"
    exit 0
}

# --- register ---------------------------------------------------------------

if (-not $RunDirectory) {
    throw "-RunDirectory is required to register the task (the sweep directory holding manifest.json)."
}
if (-not (Test-Path -LiteralPath $launcher)) {
    throw "no launcher at $launcher"
}
if (-not (Test-Path -LiteralPath (Join-Path $RunDirectory "manifest.json"))) {
    # Refused rather than registered hopefully: a task pointed at a directory
    # with no manifest would fire at every logon and log a refusal forever.
    throw "no manifest.json under $RunDirectory -- point this at a sweep directory that exists."
}

$arguments = '-NoProfile -ExecutionPolicy Bypass -NonInteractive -File "{0}" -RunDirectory "{1}"' -f `
    $launcher, $RunDirectory.TrimEnd('\')
if ($StripBomsWhenDone) {
    # Only takes effect once the run reads `completed`, and runcontrol.debom
    # refuses anything else regardless.
    $arguments += " -StripBomsWhenDone"
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments `
    -WorkingDirectory (Split-Path -Parent $PSScriptRoot)

$trigger = New-ScheduledTaskTrigger -AtLogOn -User ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
$trigger.Delay = "PT2M"

$principal = New-ScheduledTaskPrincipal -UserId ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) `
    -LogonType Interactive -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)

$description = "Continues an interrupted RingForge corpus sweep at logon. " +
               "All decisions are made by scripts\resume_sweep.ps1, which refuses to " +
               "start a second sweep and leaves an aborted one for a human."

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description $description -Force | Out-Null

"registered: $TaskName"
"  watching : $RunDirectory"
"  fires    : at logon of $env:USERNAME, two minutes in"
"  launcher : $launcher"
""
Show-Status
