<#
.SYNOPSIS
  Put a tracer address on the guest's clipboard, repeatedly, and record what
  comes back.

.DESCRIPTION
  `0bw` phase 3. The implant's beacon has two methods and only one has ever been
  seen:

      method=refresh&guid=            check in            OBSERVED, twice
      method=send&guid=&address=      report a swap       never

  Run `d2f8fe51` established that the response body is not what withholds the
  second one: an empty 200 changed nothing -- same single beacon, same
  36-second lifetime, no `send`. The remaining explanation is that **there has
  never been anything to send.** No copy event has ever happened during a run,
  so nothing was ever substituted, so there was nothing to report.

  This supplies the missing event. It writes a tracer address to the clipboard,
  waits, reads it back, and records any difference. A difference *is* the
  substitution, observed from inside containment rather than through the
  analyst's own clipboard -- which is how it was found on 22 Aug, and which cost
  a day.

  **Run it for the whole detonation, not a timed window.** The payload's spawn
  time moved between runs (t125, then t158) and it lives 36 seconds. Timing the
  loop against a predicted window is how you get one run that proves nothing.

.PARAMETER Seconds
  How long to keep baiting. Default 900.

  **It was 420, and that was too short by the width of the experiment.** On the
  first run the loop was started before the GUI was set up, spent 5.7 minutes of
  its budget waiting for the operator, and expired at t+79 -- seventy-nine
  seconds before the payload spawned at t158. Nothing was watching the clipboard
  during the only window that mattered. The `send` beacon still fired, because
  the clipboard *retained* the last value written, but the substitution question
  it was built to answer went unobserved.

.PARAMETER IntervalMs
  Delay between writing the clipboard and reading it back, and between rounds.
  The clipper polls; too fast wastes cycles and too slow can miss the window.

.PARAMETER Address
  The address written. Defaults to the ETH tracer, which is the one already
  *proven* to be substituted -- on 22 Aug it came back as the attacker's wallet.

.PARAMETER Log
  JSONL, one record per round. **Written to a file on purpose.** Terminal output
  copied out of a detonated guest is not evidence -- that is exactly what this
  tool measures -- so the record must not pass through the clipboard.

.PARAMETER AllFormats
  Cycle several address formats rather than only ETH, to learn which of the
  seventeen wallet types the clipper acts on. Costs coverage of ETH per unit
  time, so it is off by default: prove the mechanism first, enumerate later.

.EXAMPLE
  .\scripts\clipboard_bait.ps1 -Seconds 420 -Log C:\clipboard-bait.jsonl

.NOTES
  **Disable the clipboard bridge before running this.** With
  `clipboard=bidirectional` a substitution in the guest reaches the host
  clipboard, which is the 22 Aug incident reproduced deliberately.
  **Nothing closes it for you.** Containment covers the network only, on purpose
  -- see the comment on `Set-Containment`. Close it yourself with
  `VBoxManage controlvm <vm> clipboard mode disabled`, and re-open it afterwards;
  this script warns from inside but cannot read the host setting to check.

  This runs as an extra `powershell.exe` inside the run window. It will appear
  in Procmon and Sysmon output, and analyzer-attribution filters may or may not
  exclude it -- read spawned-process lists with that in mind.
#>

[CmdletBinding()]
param(
  [int]$Seconds = 900,
  [int]$IntervalMs = 500,
  [string]$Address = "0xC0FFEE0000000000000000000000000000C0FFEE",
  [string]$Log = "",
  [switch]$AllFormats
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Hit($m)  { Write-Host "[!] $m" -ForegroundColor Magenta }
function Write-Warn2($m){ Write-Host "[!] $m" -ForegroundColor Yellow }

# The tracer set. Synthetic and greppable on purpose: finding one of these in a
# beacon body is proof the implant relayed what it was given, and finding
# anything else there names which wallet it substituted instead.
#
# ETH first and alone by default because it is the only one *measured* to be
# substituted. The rest are format-plausible baits, not confirmed triggers, and
# a clipper that validates a checksum may ignore them -- which is itself worth
# knowing, but not at the cost of the run that proves the mechanism.
$script:Baits = @(
  @{ kind = "eth";   value = $Address }
  @{ kind = "btc";   value = "1C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEabcdefgh" }
  @{ kind = "btcb";  value = "bc1qc0ffeec0ffeec0ffeec0ffeec0ffeec0ffee00" }
  @{ kind = "ltc";   value = "LC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEabcdef" }
  @{ kind = "doge";  value = "DC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEabcdef" }
  @{ kind = "trx";   value = "TC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEabcd" }
)

if (-not $Log) {
  $Log = Join-Path (Get-Location).Path "clipboard_bait.jsonl"
}

function Write-Record($record) {
  # Appended immediately rather than buffered: the interesting case is a run
  # that ends unexpectedly, and a buffer lost on exit is the one record that
  # mattered.
  #
  # **AppendAllText rather than Add-Content -Encoding utf8.** The latter writes a
  # UTF-8 BOM in PowerShell 5.1, which lands at the head of the first JSON line
  # and makes it fail to parse -- silently, if the reader skips bad lines, which
  # is exactly what happened to the first run's `start` record. The same
  # preamble also turned a "truncate this file" step into a 3-byte file earlier
  # the same day.
  $json = ($record | ConvertTo-Json -Compress -Depth 4)
  [System.IO.File]::AppendAllText($Log, $json + [Environment]::NewLine,
                                  (New-Object System.Text.UTF8Encoding($false)))
}

function Test-ClipboardBridge {
  <#
    A guest cannot read the VM's clipboard-mode setting directly. What it can
    do is name the risk rather than let it pass unmentioned, because the
    consequence lands on the host and not here.
  #>
  $ga = Get-Service -Name "VBoxService" -ErrorAction SilentlyContinue
  if ($ga -and $ga.Status -eq "Running") {
    Write-Warn2 "Guest Additions are running, so a shared clipboard MAY be active."
    Write-Warn2 "If the host's clipboard mode is not 'disabled', a substitution here"
    Write-Warn2 "reaches the HOST clipboard -- the 22 Aug incident, on purpose."
    Write-Warn2 "Close it on the host with:"
    Write-Warn2 "  VBoxManage controlvm <vm> clipboard mode disabled"
    Write-Warn2 "(Nothing does this for you: containment covers the network only,"
    Write-Warn2 " deliberately -- see the comment on Set-Containment in vm_snapshot.ps1.)"
  }
}

Write-Info "Clipboard bait -- 0bw phase 3"
Write-Info "log      : $Log"
Write-Info "duration : ${Seconds}s, every ${IntervalMs}ms"
Write-Info "formats  : $(if ($AllFormats) { ($script:Baits.kind) -join ', ' } else { 'eth' })"
Test-ClipboardBridge
Write-Host ""

$started = Get-Date
Write-Record @{
  kind = "start"
  time = $started.ToUniversalTime().ToString("o")
  seconds = $Seconds
  interval_ms = $IntervalMs
  all_formats = [bool]$AllFormats
  baits = @($script:Baits | ForEach-Object { $_.value })
}

$deadline = $started.AddSeconds($Seconds)
$round = 0
$hits = 0
$errors = 0
$blanks = 0
$index = 0
$script:LastPhase = ""
$script:Phases = @()

while ((Get-Date) -lt $deadline) {
  $round++
  $bait = if ($AllFormats) { $script:Baits[$index % $script:Baits.Count] } else { $script:Baits[0] }
  $index++

  $wrote = $bait.value
  $readBack = ""
  $failure = ""

  try {
    Set-Clipboard -Value $wrote
    Start-Sleep -Milliseconds $IntervalMs
    # -Raw so a multi-line paste is not silently collapsed into an array, which
    # would compare unequal for a reason that has nothing to do with the sample.
    $readBack = [string](Get-Clipboard -Raw -ErrorAction Stop)
  } catch {
    $failure = $_.Exception.Message
    $errors++
  }

  # **An empty read-back is not a substitution, and calling it one cried wolf
  # on the first run.** `$readBack -ne $wrote` is true for "" as readily as for
  # the attacker's wallet, so a clipboard that came back blank printed
  # SUBSTITUTED in magenta with nothing on the `read` line. Blank means the read
  # lost -- an API race, or another process holding the clipboard, which a
  # polling clipper would produce -- and that is worth recording under its own
  # name rather than as the finding this tool exists to report.
  $blank   = (-not $failure) -and ($readBack -eq "")
  $changed = (-not $failure) -and (-not $blank) -and ($readBack -ne $wrote)

  # **Case-only differences are still substitutions.** The clipper rewrites in
  # EIP-55 form, so the first swap observed on 22 Aug looked like a formatting
  # quirk: same address, different case. Recorded separately so it cannot be
  # dismissed as noise a second time.
  $caseOnly = $changed -and ($readBack.ToLower() -eq $wrote.ToLower())

  # **Phase, not just state.** The interesting thing this tool records is not
  # any single round but the sequence: quiet, then substituting, then the
  # clipboard held shut. Run `bait5` went 78 clean rounds, 188 substituted, then
  # 428 locked -- and that shape is the finding. Tracking it here means the
  # script can announce a transition as it happens and summarise it at the end,
  # instead of leaving both to be reconstructed from the log afterwards.
  $phase = if ($failure) { "locked" } elseif ($changed) { "substituting" }
           elseif ($blank) { "blank" } else { "clean" }

  if ($phase -ne $script:LastPhase) {
    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    switch ($phase) {
      "locked"       { Write-Warn2 "round ${round} (+${elapsed}s): clipboard LOCKED -- cannot open it at all. Rounds continue; this line will not repeat." }
      "substituting" { Write-Hit  "round ${round} (+${elapsed}s): SUBSTITUTION BEGINS" }
      "clean"        {
        # "again" is only true after something went wrong; on the first round it
        # would be quietly misleading about what has been observed so far.
        $word = if ($script:LastPhase) { "readable again" } else { "readable" }
        Write-Ok "round ${round} (+${elapsed}s): clipboard $word, tracer intact"
      }
      "blank"        { Write-Warn2 "round ${round} (+${elapsed}s): reads coming back empty" }
    }
    $script:Phases += @{ round = $round; elapsed = $elapsed; phase = $phase
                         time = (Get-Date).ToUniversalTime().ToString("o") }
    Write-Record @{ kind = "phase"; phase = $phase; round = $round
                    elapsed_seconds = $elapsed
                    time = (Get-Date).ToUniversalTime().ToString("o") }
    $script:LastPhase = $phase
  }

  if ($changed) {
    $hits++
    $label = if ($caseOnly) { "CASE-ONLY (still a rewrite)" } else { "SUBSTITUTED" }
    Write-Hit "round ${round}: $label"
    Write-Hit "  wrote : $wrote"
    Write-Hit "  read  : $readBack"
  } elseif ($blank) {
    $blanks++
    Write-Verbose "round ${round}: clipboard read back empty"
  } elseif ($failure) {
    # **A locked clipboard used to print nothing at all.** The loop kept
    # running and the console went silent, which reads as a hung script: on run
    # `bait5` it looked like the bait had stopped at round 266 when it was
    # working normally 400 rounds later. The transition above says it once;
    # this keeps a slow pulse so the window never looks dead.
    if (($round % 60) -eq 0) {
      $elapsed = [int]((Get-Date) - $started).TotalSeconds
      Write-Warn2 "round ${round} (+${elapsed}s): still locked out ($errors failed rounds)"
    }
  }

  Write-Record @{
    kind      = "round"
    time      = (Get-Date).ToUniversalTime().ToString("o")
    round     = $round
    bait_kind = $bait.kind
    wrote     = $wrote
    read_back = $readBack
    changed   = [bool]$changed
    case_only = [bool]$caseOnly
    blank     = [bool]$blank
    error     = $failure
  }

  Start-Sleep -Milliseconds $IntervalMs
}

$summary = @{
  kind    = "summary"
  time    = (Get-Date).ToUniversalTime().ToString("o")
  rounds  = $round
  hits    = $hits
  errors  = $errors
  blanks  = $blanks
  started = $started.ToUniversalTime().ToString("o")
  ended   = (Get-Date).ToUniversalTime().ToString("o")
  # The sequence, not just the totals. `hits: 186` says substitution happened;
  # it does not say it began at +165s, ran for 195s and stopped because the
  # clipboard was taken and held. That shape is what predicts the next run.
  phases  = $script:Phases
  # The reading that matters, stated rather than left to be inferred from a
  # count of zero -- which is the shape of result this bench keeps misreading.
  note    = if ($hits -gt 0) {
              "Substitution observed inside containment."
            } elseif ($errors -ge $round) {
              "Every round failed to touch the clipboard: this measured nothing."
            } else {
              "No substitution in ${round} rounds. That is only evidence if the payload was alive for some of them: compare `started`/`ended` here against the SecurityHealthHost spawn and exit offsets. On the first run they did not overlap at all, and the absence meant nothing."
            }
}
Write-Record $summary

Write-Host ""
Write-Ok "rounds: $round   substitutions: $hits   locked: $errors   blank: $blanks"

# **The timeline, printed.** It was always in the log and never on the screen,
# so run `bait5`'s three-phase shape -- quiet, substituting, locked -- had to be
# reconstructed afterwards from timestamps. An operator who can see it as it
# happens knows whether the window covered the interesting part.
if ($script:Phases.Count -gt 0) {
  Write-Host ""
  Write-Info "phases (seconds from bait start):"
  foreach ($p in $script:Phases) {
    Write-Info ("  +{0,-6}s  round {1,-5}  {2}" -f $p.elapsed, $p.round, $p.phase)
  }
  if ($script:LastPhase -eq "locked") {
    Write-Warn2 "Ended while still locked out: the clipboard was never released."
  }
}

Write-Host ""
Write-Info $summary.note
Write-Info "record: $Log"
