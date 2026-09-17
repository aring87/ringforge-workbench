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
  [switch]$WhatIfOnly,
  # Refuse to apply a provisioning drop from the exchange. Use it for a
  # malicious corpus: the exchange is guest-writable and survives a
  # snapshot restore, so self-update is a persistence-across-revert path
  # until delivery is mounted read-only.
  [switch]$NoSelfUpdate
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
# Same reason as the two above, and the error handler now reads it: under
# StrictMode an unassigned variable throws, so a failure before the local
# work directory is chosen would kill the handler instead of being reported.
$localRoot = ""

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

function Invoke-SelfUpdate {
  <#
    Apply the newest provisioning drop on the exchange, if it is newer than
    this clone.

    Runs the script *from the drop* rather than the copy in the clone. The
    clone's copy is by definition the old one, and a provisioning step that
    cannot deliver improvements to itself needs the trip to the console it
    exists to remove.

    The drop directory is named for the commit it carries, so the common case
    -- already up to date -- costs one `git rev-parse` and no work. A name
    that does not parse is treated as "might be newer" and applied, because
    the script itself is idempotent: the fetch and `--ff-only` merge are no-ops
    on a clone that already has the commit.
  #>
  param([string]$Exchange)

  $drop = Get-ChildItem -LiteralPath $Exchange -Directory -Filter "provision-*" `
    -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $drop) { Write-Log "self-update: no provisioning drop on the exchange"; return }

  $script = Join-Path $drop.FullName "provision_guest.ps1"
  if (-not (Test-Path -LiteralPath $script)) {
    Write-Log "self-update: $($drop.Name) carries no provision_guest.ps1"
    return
  }

  $head = ""
  try {
    Push-Location $Repo
    try { $head = (& git rev-parse --short HEAD).Trim() } finally { Pop-Location }
  } catch { }

  $wanted = $drop.Name -replace '^provision-', ''
  if ($head -and $wanted -and $wanted.StartsWith($head)) {
    Write-Log "self-update: already at $head, $($drop.Name) has nothing to add"
    return
  }

  Write-Log "self-update: applying $($drop.Name) over $head"
  & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File $script -Drop $drop.FullName -Repo $Repo
  $code = $LASTEXITCODE

  $now = ""
  try {
    Push-Location $Repo
    try { $now = (& git rev-parse --short HEAD).Trim() } finally { Pop-Location }
  } catch { }
  # The commit is logged either way, and the log comes home. Which code a run
  # was analysed by is provenance, not a detail -- the host's manifest records
  # its own half and the two disagreeing has to be visible.
  Write-Log "self-update: exit $code, clone now at $now"
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

  # **Self-update, and only on a boot that is not a run.**
  #
  # Every code fix has needed a trip to the guest console, because there is no
  # remote-execution route in by design. The host already stages everything
  # required -- a bundle, wheels, and the provisioning script itself -- in a
  # `provision-<commit>` directory on the exchange, and the guest can apply it
  # unaided.
  #
  # **It is gated on there being no sample, and that gate is the whole
  # design.** The controller always delivers before it boots, so a sweep boot
  # always has a sample and never updates. Without that, a corpus could have
  # sample 1 and sample 60 analysed by different code with nothing recording
  # the change -- the exact provenance failure the manifest exists to prevent.
  #
  # **Residual risk, stated rather than buried.** The exchange is writable by
  # this guest, which means a sample running with administrator rights could
  # plant its own `provision-*` directory. It would gain nothing *in* the
  # guest, where it already has those rights, and the script runs here rather
  # than on the host -- but the exchange is the one thing that survives a
  # snapshot restore, so this is a persistence-across-revert path that did not
  # exist before. It is reachable only on a later boot that carries no sample,
  # which is a human provisioning boot rather than anything a sweep does.
  # The real fix is the read-only-in delivery the design already calls for,
  # and until that exists **pass -NoSelfUpdate for a malicious corpus.**
  if (-not $NoSelfUpdate) {
    if (Get-DeliveredSample -Work $work) {
      Write-Log "self-update: skipped, a sample is present (this is a run)"
    } else {
      try { Invoke-SelfUpdate -Exchange $exchange } catch {
        # Never fatal. A guest that refuses to analyse because an update
        # failed turns a code problem into lost corpus samples.
        Write-Log "self-update FAILED, continuing on the clone we have: $($_.Exception.Message)"
      }
    }
  }

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

  # **The analysis runs on a LOCAL disk, never on the share.** Measured
  # 17 Sep on the first real detonation: with the case directory on
  # `\\VBOXSVR\...`, Procmon started, could not be terminated (rc=1), left
  # its `procmon/` directory completely empty, and took the orchestrator
  # down with it at "Exporting Procmon CSV" -- so no
  # `dynamic_run_summary.json` was written and `combine` reported the
  # dynamic module absent despite 891 MB of real evidence sitting on disk.
  # Procmon's backing file is written by its kernel driver, which does not
  # deal with a network share; procdump, running in user mode, wrote to the
  # same UNC path without complaint, which is why this was not obvious.
  #
  # Working locally also stops ~900 MB being streamed over a shared folder
  # *during* the run, and shrinks the window in which a machine executing
  # malware is writing into a host directory. The finished case is copied
  # to the exchange in one pass at the end, before `done` is signalled.
  $localRoot = "C:\ProgramData\RingForge\work"
  if (Test-Path -LiteralPath $localRoot) {
    Remove-Item -LiteralPath $localRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  New-Item -ItemType Directory -Force -Path $localRoot | Out-Null
  if (-not (Test-Path -LiteralPath $localRoot)) {
    # Not a fallback to the share. Falling back would silently reproduce the
    # empty-Procmon failure this exists to prevent, and a case with no
    # process telemetry that looks complete is worse than a recorded void.
    throw "could not create the local work directory '$localRoot'"
  }
  Write-Log "local work: $localRoot"
  $env:CASE_ROOT_DIR = $localRoot

  Push-Location $Repo
  try {
    $py = Join-Path $Repo ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $py)) { $py = "python" }

    Write-Log "running static triage"
    & $py -m ringforge.cli scan $sample.FullName --case $caseName --json |
      Out-File -LiteralPath (Join-Path $localRoot "scan.json") -Encoding utf8

    # **The detonation, which this agent did not do for its first 102
    # samples.** It ran `scan` and `combine` and nothing else, so every swept
    # sample was statically analysed and none was ever executed -- a case
    # folder full of capa and FLOSS output looks like a finished analysis
    # until you read `modules_run`. `scan` never runs anything; `detonate`
    # is the one that does.
    $caseHome = Join-Path $localRoot $caseName
    Write-Log "detonating (this EXECUTES the sample)"

    # **Both streams are captured, and the first failure proved why.** The
    # agent used to pipe stdout to a file and let stderr go to a console
    # nobody would ever see again: the orchestrator threw, `detonate.json`
    # came home empty, and the traceback died with the guest at the next
    # restore. The cause had to be inferred from a status log instead of
    # read. `Start-Process` rather than `2>` because PowerShell 5.1 wraps a
    # native command's stderr in ErrorRecords and sets `$?` to false even on
    # a clean exit, which would make every run look failed.
    $detonateOut = Join-Path $localRoot "detonate.json"
    $detonateErr = Join-Path $localRoot "detonate.stderr.txt"
    $proc = Start-Process -FilePath $py -NoNewWindow -Wait -PassThru `
      -ArgumentList @('-m', 'ringforge.cli', 'detonate', $sample.FullName,
                      '--case-dir', $caseHome, '--json') `
      -RedirectStandardOutput $detonateOut -RedirectStandardError $detonateErr
    $detonateExit = $proc.ExitCode

    if ($detonateExit -eq 4) {
      # Containment refused the run. Fatal on purpose and it must stay fatal:
      # carrying on would detonate the rest of a sweep on a guest that can
      # reach the network. No `done` is written, so the host records a void
      # run rather than a thin one.
      throw "containment refused the detonation; see detonate.json"
    }
    if ($detonateExit -ne 0) {
      # Anything else is a coverage gap, not a reason to lose the case. The
      # static half is real evidence and `combine` reports the dynamic module
      # as absent, which is the distinction this project exists to keep --
      # "we could not look" is not "we looked and found nothing".
      Write-Log "DETONATION FAILED (exit $detonateExit); continuing so the case comes home with the gap recorded"
      $tail = try { (Get-Content -LiteralPath $detonateErr -Tail 5) -join " | " } catch { "" }
      if ($tail) { Write-Log "detonate stderr tail: $tail" }
    } else {
      Write-Log "detonation finished"
    }

    Write-Log "combining"
    & $py -m ringforge.cli combine $caseHome --json |
      Out-File -LiteralPath (Join-Path $localRoot "combined.json") -Encoding utf8
  }
  finally {
    Pop-Location
  }

  # **The one pass onto the share, and it happens before `done`.** The host
  # powers the guest off the moment `done` appears and then collects, so a
  # `done` written before this copy finishes would hand it a half-imported
  # case that looks complete. Ordering is the contract here exactly as it is
  # on the host side.
  Write-Log "copying the case to the exchange"
  Copy-Item -LiteralPath $caseHome -Destination $work -Recurse -Force
  foreach ($f in @("scan.json", "detonate.json", "detonate.stderr.txt", "combined.json")) {
    $src = Join-Path $localRoot $f
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $work -Force }
  }

  # The agent's own log goes home too. It is written to a local disk so that
  # a failure to *reach* the exchange is still recorded somewhere -- but the
  # next restore discards the guest's disk, so a copy that never leaves is a
  # copy nobody reads. This is what made the first detonation failure take an
  # hour to diagnose instead of a minute.
  try { Copy-Item -LiteralPath $LogFile -Destination (Join-Path $work "agent.log") -Force } catch { }

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
      # **Especially on this path.** A failed run is the one whose log is
      # worth reading, and it is also the one the host's closing restore is
      # about to erase. Best effort: if the exchange is what failed, there is
      # nothing to copy it to, and the guest-local copy is all there is.
      try { Copy-Item -LiteralPath $LogFile -Destination (Join-Path $work "agent.log") -Force } catch { }
      if ($localRoot -and (Test-Path -LiteralPath (Join-Path $localRoot "detonate.stderr.txt"))) {
        try {
          Copy-Item -LiteralPath (Join-Path $localRoot "detonate.stderr.txt") `
            -Destination $work -Force
        } catch { }
      }
    }
  } catch { }
  exit 1
}
