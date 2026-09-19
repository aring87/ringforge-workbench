<#
.SYNOPSIS
  Continues an interrupted corpus sweep, safely enough to run unattended.

.DESCRIPTION
  Runs on the HOST. This is the thing a scheduled task fires at logon so that a
  multi-day corpus survives a restart; see register_resume_task.ps1 for the
  task, and *`--resume`, and what it refuses* in docs/HANDOFF.md for the flag
  it drives.

  The problem it solves was measured rather than imagined. `benign-102-v2` was
  killed 38 minutes into its first sample by an ordinary restart, because a
  detached sweep dies with the session however it was launched -- `nohup` and
  `Start-Process` both. At 102 samples and four to five days, that will happen
  again, and every occurrence costs whatever sample was mid-flight plus however
  long it takes somebody to notice.

  Four things here are deliberate.

  EVERY RUN PARAMETER IS READ BACK OUT OF THE MANIFEST, not passed in and not
  hardcoded. The manifest already records the source, exchange, guest, baseline,
  timeouts and policy the run was started with, because a corpus row has to be
  interpretable years later. Reading them back is what guarantees the resumed
  leg is the same measurement as the one it continues: there is no second copy
  of the command line to drift out of step, and this script does not need to be
  edited when a different corpus is running. The only thing it supplies is
  where the repo and its interpreter are.

  IT REFUSES TO START A SECOND SWEEP. Two controllers on one guest would fight
  over snapshot restores mid-detonation, and `sweep.py` already refuses to run
  two guests for a related reason (see its module docstring). A manifest in
  state `running` is ambiguous on its own -- it looks identical whether the
  sweep is alive or was killed -- so the liveness question is answered against
  the process table rather than against the file. Any `runcontrol.sweep`
  process at all, on any run id, stops this.

  AN ABORTED SWEEP IS LEFT FOR A HUMAN. `--abort-after` fires when three
  samples in a row observe nothing, which is a statement about the bench and
  not about the samples. Automatically resuming into a broken guest would turn
  a signal somebody needs to read into three more void rows per logon. Only an
  interrupted run (`running`) or one that never started (`refused`) is picked
  up.

  IT WAITS FOR THE VOLUME. The exchange, corpus and runs directories are on an
  external drive, and at logon it may not be mounted yet. A task that fired
  three seconds too early and concluded there was no run to resume would be
  worse than no task, so the manifest is waited for rather than tested once.

  Every decision is appended to <run id>.autoresume.log beside the run
  directory, including the decisions to do nothing. A task that silently
  declines to act is indistinguishable from a task that is not registered.

.PARAMETER RunDirectory
  The sweep directory: the one holding manifest.json beside cases/.

.PARAMETER Repo
  Where the workbench is checked out. Defaults to this script's parent, which
  is correct whenever the script is run from the repo it belongs to.

.PARAMETER WaitForVolumeSeconds
  How long to wait for RunDirectory to appear before giving up. The external
  drive is usually there within a few seconds of logon; the default is
  generous because the cost of waiting is nothing and the cost of giving up
  early is a stalled corpus nobody notices.

.PARAMETER StripBomsWhenDone
  Once the run reads `completed`, strip the byte-order marks the guest's
  PowerShell left on its JSON (`runcontrol.debom`). Does nothing until then,
  and the tool refuses anything else regardless.

.PARAMETER RescoreWhenDone
  Once the run reads `completed`, re-score the corpus against the current
  scoring code (`runcontrol.rescore`). A corpus is scored in the guest at
  detonation time and `combine` reads that score back rather than recomputing
  it, so a scoring fix made after a run started cannot otherwise reach it.
  Runs after the BOM strip; see the ordering note at the call.

.PARAMETER DryRun
  Make every check and print the decision and the exact command, but launch
  nothing. This is how the branches below get exercised without a hypervisor,
  and given that every bug in this bench's PowerShell has cost a 45-minute
  run, it is not optional equipment.

.EXAMPLE
  .\scripts\resume_sweep.ps1 -RunDirectory G:\ringforge-runs\benign-102-v2 -DryRun

.NOTES
  Exit codes: 0 acted or correctly did nothing, 1 could not look, 2 refused
  and wants a human.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunDirectory,

    [string]$Repo,

    [int]$WaitForVolumeSeconds = 300,

    [switch]$StripBomsWhenDone,

    [switch]$RescoreWhenDone,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$script:LogPath = $null

function Write-Line {
    param([string]$Text)
    $line = "{0}  {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $Text
    Write-Output $line
    if ($script:LogPath) {
        # Never fatal. Losing the log line must not lose the resume.
        try { Add-Content -Path $script:LogPath -Value $line -Encoding utf8 } catch { }
    }
}

function ConvertTo-Argument {
    <#  Start-Process joins -ArgumentList with spaces and quotes NOTHING, so a
        path containing a space arrives at the far side as two arguments and
        the command fails in a way that reads like a bad path rather than bad
        quoting. Measured here: a probe passing `-c "import time; ..."` as an
        array had python receive `-c import` and die on a syntax error.

        This is the same class of bug as VBoxManage re-splitting its own
        --description, which this bench has now paid for twice -- see *Traps
        paid for* in docs/HANDOFF.md. None of the current paths contain a
        space, which is exactly why it would sit here unnoticed until a corpus
        directory did.

        A double quote inside an argument needs the backslash-doubling dance
        that Windows command lines require. No path here has one, and half a
        quoting implementation is worse than a refusal, so it refuses. #>
    param([string]$Value)
    if ($Value -match '"') {
        throw "cannot pass an argument containing a double quote: $Value"
    }
    if ($Value -match '\s') { return '"' + $Value + '"' }
    return $Value
}

function Invoke-CorpusTool {
    <#
        .SYNOPSIS
          Run one of the corpus-editing modules and get its reasoning into the
          log.

        .DESCRIPTION
          `runcontrol.debom` and `runcontrol.rescore` are the only two tools in
          the bench that edit a corpus in place, and both are run from here
          once a run reads `completed`. They need identical handling of two
          PowerShell traps, so it lives in one place rather than twice.

          **stderr goes to a file, never `2>&1`.** In PS 5.1 merging a native
          command's stderr wraps each line in an ErrorRecord and sets `$?`
          false even on success.

          **ErrorActionPreference has to come off for the call.** This script
          runs with it on `Stop`, which makes a native command's stderr a
          TERMINATING error -- so a refusal, which is a normal and expected
          outcome for both tools, would kill the launcher before it could log
          why. Measured: it aborted the script, and the task would have
          reported failure for a tool behaving correctly.

          The exit line deliberately does not claim the corpus is unchanged.
          `debom` refuses atomically, but `rescore` can change several cases
          and fail on one, so only the tool's own output can say what it did.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Python,
        [Parameter(Mandatory = $true)][string]$RunDirectory,
        [Parameter(Mandatory = $true)][string]$ErrLog,
        [Parameter(Mandatory = $true)][string]$Doing,
        [string]$RecordPath = "",
        [string]$AlreadyDone = "",
        [switch]$Preview
    )

    # Both tools are idempotent; this only keeps the log from repeating a
    # no-op at every logon for the rest of the machine's life.
    if ($RecordPath -and (Test-Path -LiteralPath $RecordPath)) {
        Write-Line $AlreadyDone
        return
    }
    if ($Preview) {
        Write-Line ("dry run, so not {0}" -f $Doing)
        return
    }

    Write-Line $Doing
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & $Python -m $Module $RunDirectory 2>$ErrLog
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }

    foreach ($line in $lines) { Write-Line "   $line" }
    if ($code -ne 0) {
        Write-Line ("   {0} exited {1}" -f $Module, $code)
        if (Test-Path -LiteralPath $ErrLog) {
            # First few lines only. PS 5.1 writes the whole ErrorRecord
            # formatting into the file -- source line, carets, category -- and
            # the message is the part worth reading. The file keeps the rest.
            $reason = @(Get-Content -LiteralPath $ErrLog |
                        Where-Object { $_ } |
                        Select-Object -First 4)
            foreach ($line in $reason) { Write-Line "   $line" }
            Write-Line "   (full stderr: $ErrLog)"
        }
    }
}

function Get-Property {
    <#  A missing key and a null value are the same answer here, and
        PSCustomObject throws on the first where a hashtable would not. #>
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    if ($null -eq $property.Value) { return $Default }
    return $property.Value
}

# --- where things are -------------------------------------------------------

if (-not $Repo -or $Repo -eq "") {
    $Repo = Split-Path -Parent $PSScriptRoot
}
$python = Join-Path $Repo ".venv\Scripts\python.exe"

$runName = Split-Path $RunDirectory -Leaf
$outRoot = Split-Path $RunDirectory -Parent
$manifestPath = Join-Path $RunDirectory "manifest.json"
$script:LogPath = Join-Path $outRoot ("{0}.autoresume.log" -f $runName)

Write-Line ("--- fired: RunDirectory={0} DryRun={1}" -f $RunDirectory, [bool]$DryRun)

if (-not (Test-Path -LiteralPath $python)) {
    # One string, one -f. PowerShell binds + tighter than -f, so splitting a
    # message across "..." -f $x + "..." formats ($x + "...") instead and
    # quietly prints the wrong thing.
    Write-Line ("giving up: no interpreter at {0}. The venv is the only Python this bench runs; the global one silently disables features." -f $python)
    exit 1
}

# --- wait for the external drive -------------------------------------------

$deadline = (Get-Date).AddSeconds($WaitForVolumeSeconds)
$waited = $false
while (-not (Test-Path -LiteralPath $manifestPath)) {
    if ((Get-Date) -gt $deadline) {
        Write-Line ("giving up: {0} never appeared within {1}s. If the drive is simply not connected, nothing here is wrong and the next logon will retry." -f $manifestPath, $WaitForVolumeSeconds)
        exit 1
    }
    if (-not $waited) {
        Write-Line "waiting for the run directory to appear (external drive not mounted yet)"
        $waited = $true
    }
    Start-Sleep -Seconds 5
}
if ($waited) { Write-Line "the run directory appeared" }

# --- read the record --------------------------------------------------------

try {
    $document = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Line ("giving up: {0} will not parse ({1}). That file is the only record of this run and nothing here will write over it." -f $manifestPath, $_.Exception.Message)
    exit 1
}

$state = Get-Property $document "state" "(none)"
$runId = Get-Property $document "run_id" $runName
$totals = Get-Property $document "totals"
$attempted = Get-Property $totals "attempted" 0
$planned = Get-Property $totals "planned" 0

Write-Line ("manifest: run_id={0} state={1} attempted={2} of {3}" -f $runId, $state, $attempted, $planned)

# --- decide -----------------------------------------------------------------

if ($state -eq "completed") {
    Write-Line "the run finished."

    # Order matters between these two. `debom` only rewrites files the guest
    # wrote; `rescore` rewrites the run summary and regenerates
    # combined_verdict.json from it. Stripping first means the hashes `debom`
    # records describe files nothing else has touched since.
    if ($StripBomsWhenDone) {
        # The corpus was produced before the BOM fix reached the guest, which
        # self-updates only when booted with no sample -- so these files can
        # only be fixed after the fact.
        Invoke-CorpusTool -Module "runcontrol.debom" -Python $python `
            -RunDirectory $RunDirectory `
            -ErrLog (Join-Path $outRoot ("{0}.debom.err.log" -f $runId)) `
            -RecordPath (Join-Path $RunDirectory "bom_strip.json") `
            -AlreadyDone "byte-order marks were already stripped (bom_strip.json exists)" `
            -Doing "stripping byte-order marks from the corpus" `
            -Preview:$DryRun
    }

    if ($RescoreWhenDone) {
        # A corpus is scored in the guest at detonation time and `combine`
        # reads that score back rather than recomputing it, so a scoring fix
        # made after the run started cannot reach it. benign-102-v2 was scored
        # by code that counted a loopback connection as external contact.
        Invoke-CorpusTool -Module "runcontrol.rescore" -Python $python `
            -RunDirectory $RunDirectory `
            -ErrLog (Join-Path $outRoot ("{0}.rescore.err.log" -f $runId)) `
            -RecordPath (Join-Path $RunDirectory "rescore.json") `
            -AlreadyDone "verdicts were already re-scored (rescore.json exists)" `
            -Doing "re-scoring the corpus against the current scoring code" `
            -Preview:$DryRun
    }

    Write-Line "nothing else to do. This task can be unregistered."
    exit 0
}
if ($state -eq "dry_run") {
    Write-Line "nothing to do: that is a dry run's manifest, not an interrupted run."
    exit 0
}
if ($state -eq "aborted") {
    Write-Line ("REFUSING: the sweep aborted, which means three samples in a row " +
                "observed nothing and the bench is the suspect, not the samples. " +
                "Resuming would add three more void rows per logon and bury the " +
                "signal. Fix the guest, then resume by hand.")
    exit 2
}
if ($state -ne "running" -and $state -ne "refused") {
    Write-Line ("REFUSING: state '{0}' is not one this knows how to continue." -f $state)
    exit 2
}

# Is one already going? The manifest cannot answer this -- a live sweep and a
# killed one both leave `running` -- so ask the process table. Any sweep at all
# stops this, on any run id: two controllers on one guest is the failure, and
# the second one would be racing snapshot restores against the first.
$running = @()
try {
    $running = @(Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction Stop |
                 Where-Object { $_.CommandLine -and $_.CommandLine -match "runcontrol\.sweep" })
} catch {
    Write-Line ("giving up: cannot read the process table ({0}), so whether a sweep is already running is unknown. Not starting a second one on a guess." -f $_.Exception.Message)
    exit 1
}
$blocked = $false
if ($running.Count -gt 0) {
    foreach ($process in $running) {
        Write-Line ("a sweep is already running (pid {0})" -f $process.ProcessId)
    }
    if (-not $DryRun) {
        Write-Line "nothing to do: not starting a second controller on this guest."
        exit 0
    }
    # A dry run that stopped here could never show the command, because the
    # run you want to preview resuming is usually the one that is alive.
    # Launching nothing is what makes it safe to keep going and print it.
    $blocked = $true
    Write-Line "dry run: continuing anyway to show the command; a real run would have stopped above."
}

# --- rebuild the command from the run's own record --------------------------

$source = Get-Property $document "source"
$exchange = Get-Property $document "exchange"
$caseRoot = Get-Property $document "case_root"
$guest = Get-Property $document "guest"
$policy = Get-Property $document "policy"

if (-not $source -or -not $exchange -or -not $guest) {
    Write-Line "giving up: the manifest does not carry the source, exchange and guest this needs."
    exit 1
}

# The out root is the run directory's parent, and the manifest's own case_root
# has to agree. If it does not, this script is pointed at a directory that was
# moved, and the paths it would pass would put cases somewhere else.
$expectedCaseRoot = Join-Path $RunDirectory "cases"
if ($caseRoot -and ($caseRoot.TrimEnd('\') -ne $expectedCaseRoot.TrimEnd('\'))) {
    Write-Line ("REFUSING: the manifest says its cases live at {0}, but this directory implies {1}. The run has been moved; resuming would scatter it across both." -f $caseRoot, $expectedCaseRoot)
    exit 2
}

$vm = Get-Property $guest "vm"
$baseline = Get-Property $guest "baseline"
if (-not $vm -or -not $baseline) {
    Write-Line "giving up: the manifest names no vm or no baseline, and neither can be guessed."
    exit 1
}

$sweepArgs = New-Object System.Collections.Generic.List[string]
$sweepArgs.Add("-m"); $sweepArgs.Add("runcontrol.sweep")
$sweepArgs.Add($source)
$sweepArgs.Add("--vm");       $sweepArgs.Add($vm)
$sweepArgs.Add("--baseline"); $sweepArgs.Add($baseline)
$sweepArgs.Add("--exchange"); $sweepArgs.Add($exchange)
$sweepArgs.Add("--out");      $sweepArgs.Add($outRoot)
$sweepArgs.Add("--run-id");   $sweepArgs.Add($runId)

$readiness = Get-Property $guest "readiness_timeout"
if ($readiness) { $sweepArgs.Add("--readiness-timeout"); $sweepArgs.Add([string]$readiness) }
$runTimeout = Get-Property $guest "run_timeout"
if ($runTimeout) { $sweepArgs.Add("--run-timeout"); $sweepArgs.Add([string]$runTimeout) }

# Policy, so a resumed leg measures on the same terms as the leg it continues.
$attempts = Get-Property $policy "attempts"
if ($attempts) { $sweepArgs.Add("--attempts"); $sweepArgs.Add([string]$attempts) }
$abortAfter = Get-Property $policy "abort_after_consecutive_void"
if ($null -ne $abortAfter) { $sweepArgs.Add("--abort-after"); $sweepArgs.Add([string]$abortAfter) }
if (Get-Property $policy "recursive" $false) { $sweepArgs.Add("--recursive") }
$limit = Get-Property $policy "limit"
if ($limit) { $sweepArgs.Add("--limit"); $sweepArgs.Add([string]$limit) }
foreach ($extension in @(Get-Property $policy "extensions" @())) {
    $sweepArgs.Add("--ext"); $sweepArgs.Add([string]$extension)
}

$sweepArgs.Add("--resume")

# Leg numbering matches the manifest's own: the first run is leg 1 and carries
# no entry, so the next leg is however many resumptions there are, plus two.
$legs = @(Get-Property $document "resumed" @())
$leg = $legs.Count + 2
$stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$outLog = Join-Path $outRoot ("{0}.leg{1}-{2}.log" -f $runId, $leg, $stamp)
$errLog = Join-Path $outRoot ("{0}.leg{1}-{2}.err.log" -f $runId, $leg, $stamp)

try {
    $commandLine = (($sweepArgs | ForEach-Object { ConvertTo-Argument $_ }) -join " ")
} catch {
    Write-Line ("giving up: {0}" -f $_.Exception.Message)
    exit 1
}

Write-Line ("resuming as leg {0}: {1} {2}" -f $leg, $python, $commandLine)
Write-Line ("  stdout -> {0}" -f $outLog)

if ($DryRun) {
    if ($blocked) {
        Write-Line "dry run: launched nothing, and a real run would have declined -- a sweep is already going."
    } else {
        Write-Line "dry run: launched nothing"
    }
    exit 0
}

try {
    # One pre-quoted string, not the array: see ConvertTo-Argument.
    $process = Start-Process -FilePath $python -ArgumentList $commandLine `
        -WorkingDirectory $Repo -RedirectStandardOutput $outLog `
        -RedirectStandardError $errLog -WindowStyle Hidden -PassThru
} catch {
    Write-Line ("giving up: the sweep would not start ({0})" -f $_.Exception.Message)
    exit 1
}

Write-Line ("started, pid {0}" -f $process.Id)
exit 0
