<#
.SYNOPSIS
  Stops Windows Update from restarting the GUEST mid-run: disables the
  Update Orchestrator's scheduled tasks and the update services. Runs in the
  GUEST, elevated; does the work as SYSTEM. Refuses anywhere else.

.DESCRIPTION
  **Why the policy was not enough.** Between 13 and 19 Nov the analysis guest
  restarted itself on ten held-out runs, always between about 04:20 and 05:50
  local. On 21 Nov the guest's own event 1074 named the process:
  `C:\WINDOWS\uus\AMD64\MoUsoCoreWorker.exe`, "Operating System: Service
  pack (Planned)". `provision_guest.ps1` then set the classic policy values
  (`NoAutoUpdate`, `NoAutoRebootWithLoggedOnUsers`), and the baseline that
  carried them restarted anyway: booted with its clock at 04:05, it ran
  `Schedule Scan` (04:10), `Start Oobe Expedite Work` (04:20), `Schedule
  Work` (04:28) and restarted at 04:42. The OOBE expedite path is the
  expedited-update mechanism, and it does not consult those values.

  So this disables the machinery itself: every task under the Update
  Orchestrator, Windows Update and WaaSMedic task folders, and the services
  behind them (`UsoSvc`, `wuauserv`, `WaaSMedicSvc`, `uhssvc`). The tasks are
  protected from administrators, so the work runs as SYSTEM, through a
  one-shot scheduled task that this script registers, starts, waits for and
  removes.

  **Only in the analysis guest.** A machine that never updates is wrong
  everywhere except a disposable guest that is restored from a snapshot for
  every run and has no internet during one. The script refuses to run unless
  the machine reports itself as a VirtualBox VM, so it cannot be pointed at a
  host by mistake.

  Each item is attempted and recorded, never assumed; the result is JSON so
  `provision_guest.ps1` can put it in its receipt.

.PARAMETER Result
  Where the SYSTEM half writes its JSON result.

.PARAMETER AsSystem
  Internal: this invocation is the SYSTEM half.
#>
[CmdletBinding()]
param(
  [string]$Result = "C:\ProgramData\RingForge\no-update-restarts.json",
  [switch]$AsSystem
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$model = try { "$((Get-CimInstance Win32_ComputerSystem).Model)" } catch { "" }
if ($model -notmatch "VirtualBox") {
  throw ("refusing: this machine reports model '$model', not a VirtualBox VM. " +
         "This script disables Windows Update and is for the disposable " +
         "analysis guest only.")
}

$taskPaths = @("\Microsoft\Windows\UpdateOrchestrator\",
               "\Microsoft\Windows\WindowsUpdate\",
               "\Microsoft\Windows\WaaSMedic\")
$services = @("UsoSvc", "wuauserv", "WaaSMedicSvc", "uhssvc")

if (-not $AsSystem) {
  $dir = Split-Path -Parent $Result
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  Remove-Item -LiteralPath $Result -Force -ErrorAction SilentlyContinue
  $name = "RingForge disable update restarts (one-shot)"
  $arg = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`" -AsSystem -Result `"$Result`""
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Force | Out-Null
  try {
    Start-ScheduledTask -TaskName $name
    $deadline = (Get-Date).AddMinutes(3)
    while (-not (Test-Path -LiteralPath $Result) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    Start-Sleep -Seconds 1
  } finally {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  }
  if (-not (Test-Path -LiteralPath $Result)) { throw "the SYSTEM half wrote no result within 3 minutes" }
  Get-Content -LiteralPath $Result -Raw
  exit 0
}

# --- the SYSTEM half --------------------------------------------------------
$out = [ordered]@{
  when           = (Get-Date).ToUniversalTime().ToString("o")
  identity       = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  tasks_disabled = @()
  tasks_failed   = @()
  services       = [ordered]@{}
  ok             = $false
}
try {
  foreach ($path in $taskPaths) {
    foreach ($task in @(Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue)) {
      $full = "$($task.TaskPath)$($task.TaskName)"
      try {
        Disable-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction Stop | Out-Null
        $out.tasks_disabled += $full
      } catch {
        $out.tasks_failed += "${full}: $($_.Exception.Message)"
      }
    }
  }
  foreach ($svc in $services) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
    if (-not (Test-Path -LiteralPath $key)) { $out.services[$svc] = "absent"; continue }
    try { Stop-Service -Name $svc -Force -ErrorAction Stop } catch { }
    $note = ""
    try { Set-ItemProperty -LiteralPath $key -Name Start -Value 4 -ErrorAction Stop }
    catch { $note = " (could not set: $($_.Exception.Message))" }
    $start = try { (Get-ItemProperty -LiteralPath $key -Name Start).Start } catch { "?" }
    $state = try { "$((Get-Service -Name $svc).Status)" } catch { "?" }
    $out.services[$svc] = "start=$start status=$state$note"
  }
  # The two that run the restart path must be off; WaaSMedicSvc and uhssvc
  # are recorded either way, because their keys can refuse even SYSTEM.
  $out.ok = ($out.services["UsoSvc"] -like "start=4*") -and
            ($out.services["wuauserv"] -like "start=4*") -and
            (@($out.tasks_disabled | Where-Object { $_ -like "\Microsoft\Windows\UpdateOrchestrator\*" }).Count -gt 0)
} catch {
  $out["error"] = $_.Exception.Message
}
[System.IO.File]::WriteAllText($Result, ($out | ConvertTo-Json -Depth 4),
  (New-Object System.Text.UTF8Encoding($false)))
