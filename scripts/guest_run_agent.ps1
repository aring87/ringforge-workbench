<#
.SYNOPSIS
  Watches the exchange for a delivered sample, runs the analysis, and signals
  the host. Runs in the GUEST.

.DESCRIPTION
  The guest half of the run controller. `runcontrol/loop.py` on the host
  restores a snapshot, cuts the cable, drops a sample into
  `<exchange>\current`, and boots this machine. This agent is what makes the
  rest happen, and what tells the host it happened.

  **Two files are the entire protocol**, written here and only ever read by the
  host:

      ringforge-ready   collection is up and a run is starting
      ringforge-done    the run finished and results are written

  Nothing listens on a socket, the host holds no credentials for this machine,
  and it works identically whether the exchange is a shared folder or a mounted
  disk. The host never writes these two; this agent never reads them.

  **Why `ready` is a separate signal from `done`.** Measured 31 Aug: an
  `ONSTART` capture task started 3m51s *after* the sample's own `ONLOGON`
  payload, because Task Scheduler delays and throttles boot-triggered tasks.
  Booted is not started. So the host waits for proof that something is
  watching rather than assuming it because the machine came up, and a run whose
  `ready` never arrives is recorded as a **void run** rather than as a quiet
  sample -- the same distinction the scoring model draws between "we looked and
  found nothing" and "we could not look".

  **`ready` means a run is beginning, not that every collector is present.** A
  bench missing Sysmon still produces a real run with a recorded coverage gap,
  and refusing to start would turn a degraded bench into no bench. What must
  never happen is `ready` without a run, so it is written immediately before
  the analysis is invoked and not a moment earlier.

.PARAMETER Exchange
  The exchange directory as this guest sees it. Defaults to discovery:
  `\\VBOXSVR\ringforge`, then any drive root holding a `current` directory.

.PARAMETER WorkDir
  The subdirectory the controller owns. Must match `runcontrol.loop.RUN_DIR`.

.PARAMETER WaitSeconds
  How long to wait for a sample to appear before giving up. Generous: the host
  delivers before boot, so a sample should already be there, and waiting costs
  nothing when it is.

.PARAMETER Repo
  The workbench clone in this guest. Defaults to the path this bench uses.

.NOTES
  Runs unelevated or elevated. Elevated is wanted: Procmon, Sysmon, packet
  capture and memory dumps all need Administrator, and each reports its own
  absence rather than failing the run.
#>

[CmdletBinding()]
param(
  [string]$Exchange = "",
  [string]$WorkDir = "current",
  [int]$WaitSeconds = 300,
  [string]$Repo = "C:\projects\RingForge_Analyzer\ringforge-workbench",
  [int]$Timeout = 240,
  [switch]$WhatIfOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# **Declared before anything can fail.** Under StrictMode, referencing an
# unassigned variable throws -- so the error handler's `if ($work)` threw when
# the failure happened before `$work` was set, and the agent died reporting
# nothing at all. A first run produced no signal, no error file and no way to
# tell "the task never fired" from "the task fired and failed immediately".
$work = ""
$exchange = ""

# **A guest-local log, written before the share is touched.** The exchange is
# the only channel back to the host, so a failure to reach the exchange is
# invisible on the host by construction. This log is on the guest's own disk,
# so it survives that and is readable afterwards even when the share never
# worked.
$LogDir = "C:\ProgramData\RingForge"
$LogFile = Join-Path $LogDir "agent.log"
try { if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null } } catch { }

function Write-Log($msg) {
  $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $line = "[$stamp] $msg"
  Write-Host $line
  try { Add-Content -LiteralPath $LogFile -Value $line -Encoding utf8 } catch { }
}

function Write-Identity {
  <#
    Who am I and can I see the share. Both are recorded on every run because
    they are the two things that decide whether this agent can work at all,
    and neither is visible from the host.

    **A SYSTEM-context task may not be able to reach the share.** VirtualBox
    shared folders are mounted by VBoxService per interactive session; the
    redirector is not necessarily present in session 0. If that is what is
    happening, the transport and the trigger are coupled: a shared-folder
    exchange needs the agent to run as a logged-on user, and a SYSTEM trigger
    needs a transport SYSTEM can see -- a second virtual disk rather than a
    share.
  #>
  $who = try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "unknown" }
  Write-Log "identity: $who"
  Write-Log "session : $([System.Diagnostics.Process]::GetCurrentProcess().SessionId)"
  $share = "\\VBOXSVR\ringforge"
  foreach ($probe in @($share, "\\VBOXSVR")) {
    $seen = try { Test-Path -LiteralPath $probe } catch { $false }
    Write-Log "probe   : $probe -> $seen"
  }
  $drives = try { (Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name }) -join "," } catch { "?" }
  Write-Log "drives  : $drives"
}

function Find-Exchange {
  <#
    Discovery rather than a hardcoded drive letter. VirtualBox auto-mount picks
    the first free letter, which is not stable across boots -- a snapshot taken
    when the share landed on E: will find it on F: the day a card reader is
    attached. The UNC path is stable and always present when Guest Additions
    are running, so it is tried first.
  #>
  param([string]$Configured, [string]$WorkDir)

  if ($Configured) {
    if (Test-Path -LiteralPath $Configured) { return $Configured }
    throw "the exchange was given as '$Configured' and does not exist"
  }

  $unc = "\\VBOXSVR\ringforge"
  if (Test-Path -LiteralPath $unc) { return $unc }

  # Fall back to whichever drive root holds the controller's work directory.
  foreach ($d in (Get-PSDrive -PSProvider FileSystem | Sort-Object Name)) {
    $candidate = Join-Path $d.Root $WorkDir
    if (Test-Path -LiteralPath $candidate) { return $d.Root }
  }

  throw ("no exchange found. Tried '$unc' and every filesystem drive root for " +
         "a '$WorkDir' directory. Are Guest Additions running and the share " +
         "attached?")
}

function Get-DeliveredSample {
  <#
    The one file that is not ours. `ringforge-ready` and `ringforge-done` are
    signals, and anything else the host dropped is a run spec; the sample is
    whatever remains. Returned newest-first so a re-delivery wins, though the
    host clears the directory before every run so there should only be one.
  #>
  param([string]$Work)

  Get-ChildItem -LiteralPath $Work -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike "ringforge-*" -and $_.Extension -ne ".json" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
}

# ---------------------------------------------------------------------------

try {
  Write-Log "=== agent starting ==="
  Write-Identity
  $exchange = Find-Exchange -Configured $Exchange -WorkDir $WorkDir
  $work = Join-Path $exchange $WorkDir
  Write-Log "exchange: $exchange"
  Write-Log "work    : $work"

  if (-not (Test-Path -LiteralPath $work)) {
    throw ("'$work' does not exist. The host creates it before boot, so this " +
           "means the guest booted without a delivery -- which the host will " +
           "record as a void run rather than as a quiet sample.")
  }

  $readyFile = Join-Path $work "ringforge-ready"
  $doneFile = Join-Path $work "ringforge-done"

  # Wait for the sample. It is normally already there, because the host
  # delivers before it boots this machine.
  $deadline = (Get-Date).AddSeconds($WaitSeconds)
  $sample = $null
  while ((Get-Date) -lt $deadline) {
    $sample = Get-DeliveredSample -Work $work
    if ($sample) { break }
    Start-Sleep -Seconds 2
  }

  if (-not $sample) {
    # No `ready` written. The host times out and records a void run, which is
    # the correct outcome: nothing was observed.
    throw "no sample appeared in '$work' within ${WaitSeconds}s"
  }

  Write-Log "sample  : $($sample.Name) ($($sample.Length) bytes)"

  if (-not (Test-Path -LiteralPath $Repo)) {
    throw ("the workbench is not at '$Repo'. Pass -Repo, or clone it there. " +
           "Note that v1.12.0 moved the authored YARA rules into the package, " +
           "so a stale clone will not find them.")
  }

  # **`ready` goes out here and nowhere earlier.** Everything above can fail
  # without a run having started, and a `ready` with no run behind it would
  # turn a void run into a silent one.
  "collection up at " + (Get-Date).ToUniversalTime().ToString("o") |
    Set-Content -LiteralPath $readyFile -Encoding utf8
  Write-Log "signalled ready"

  if ($WhatIfOnly) {
    Write-Log "WhatIfOnly: not detonating"
    "what-if, nothing detonated" | Set-Content -LiteralPath $doneFile -Encoding utf8
    Write-Log "signalled done"
    exit 0
  }

  # The run itself. Output lands in the work directory so the host collects it
  # from one bounded place rather than from the whole share.
  $caseName = [IO.Path]::GetFileNameWithoutExtension($sample.Name)
  $env:CASE_ROOT_DIR = $work

  Push-Location $Repo
  try {
    $py = Join-Path $Repo ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $py)) { $py = "python" }

    Write-Log "running static triage"
    & $py -m ringforge.cli scan $sample.FullName --case $caseName --json |
      Out-File -LiteralPath (Join-Path $work "scan.json") -Encoding utf8

    Write-Log "combining"
    & $py -m ringforge.cli combine (Join-Path $work $caseName) --json |
      Out-File -LiteralPath (Join-Path $work "combined.json") -Encoding utf8
  }
  finally {
    Pop-Location
  }

  "run finished at " + (Get-Date).ToUniversalTime().ToString("o") |
    Set-Content -LiteralPath $doneFile -Encoding utf8
  Write-Log "signalled done"
  exit 0
}
catch {
  # **No `done` on failure.** The host distinguishes a run that overran from one
  # that never started, and writing `done` here would collapse the two -- a
  # failed run would present as a finished one with thin results.
  Write-Log "FAILED: $($_.Exception.Message)"
  try {
    if ($work -ne "") {
      "agent failed: $($_.Exception.Message)" |
        Set-Content -LiteralPath (Join-Path $work "ringforge-agent-error.txt") -Encoding utf8
    }
  } catch { }
  exit 1
}
