<#
.SYNOPSIS
  Brings the guest's clone up to a commit and installs the package into its
  venv, with no network. Runs in the GUEST.

.DESCRIPTION
  Two things the guest needs before it can contribute to a corpus, neither of
  which the host can do for it.

  **The host has no way in, and that is the design.** `guestcontrol` was
  rejected when the transport was chosen -- it needs Guest Additions and puts
  guest credentials on the host -- and the run agent scans what is delivered
  rather than executing it. So there is no remote-execution primitive here by
  construction, and provisioning is a thing somebody types at the console.
  This script exists so that it is one command rather than a session.

  **Why the clone is behind.** The guest is contained: NIC1's cable is off
  from the host, so `git pull` has nowhere to go. The host therefore ships a
  bundle over the exchange, which is an offline `git fetch` in a file.

  **Why the install needs flags.** `pip install -e .` uses build isolation,
  which fetches `setuptools>=68` from PyPI -- measured to fail offline. And
  `--no-build-isolation` is not the fix on its own: since Python 3.12 a venv
  is seeded with pip and *not* setuptools, so the build then fails for the
  opposite reason. Pointing pip at a local wheel directory with `--no-index`
  satisfies build isolation from disk and works whether or not the venv
  happens to have setuptools. `--no-deps` because the runtime dependencies are
  already installed here and resolving them offline would fail.

  **What it fixes.** `analyzer_version()` reads the installed package version
  through `importlib.metadata`. With nothing installed it returns `None`, and
  every verdict this guest produces is half-identified: a commit and no
  version. A corpus entry has to name its analyzer.

  A receipt is written back to the drop directory, so the host can read the
  outcome from the share instead of the operator relaying it. Same direction
  of trust as the run agent: the guest writes, the host reads.

.PARAMETER Drop
  The provisioning directory on the exchange, holding `workbench.bundle` and
  `wheels\`. Defaults to discovery under the share.

.PARAMETER Repo
  The workbench clone in this guest.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\provision_guest.ps1
#>

[CmdletBinding()]
param(
  [string]$Drop = "",
  [string]$Repo = "C:\projects\RingForge_Analyzer\ringforge-workbench",
  [switch]$SkipPull,
  [switch]$SkipInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Say($m)  { Write-Host "[*] $m" -ForegroundColor Cyan }
function Good($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

$receipt = [ordered]@{
  when          = (Get-Date).ToUniversalTime().ToString("o")
  identity      = "unknown"
  repo          = $Repo
  commit_before = $null
  commit_after  = $null
  version       = $null
  pulled        = $false
  installed     = $false
  ok            = $false
  error         = ""
}
try { $receipt.identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { }

try {
  # -- find the drop --------------------------------------------------------
  if (-not $Drop) {
    foreach ($root in @("\\VBOXSVR\ringforge")) {
      if (Test-Path -LiteralPath $root) {
        $found = Get-ChildItem -LiteralPath $root -Directory -Filter "provision-*" |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($found) { $Drop = $found.FullName; break }
      }
    }
  }
  if (-not $Drop -or -not (Test-Path -LiteralPath $Drop)) {
    throw ("no provisioning drop found. Pass -Drop, or check that the share " +
           "is mounted -- if \\VBOXSVR is not reachable, Guest Additions are " +
           "not running.")
  }
  Say "drop: $Drop"

  if (-not (Test-Path -LiteralPath $Repo)) { throw "no clone at '$Repo'" }
  Push-Location $Repo
  try {
    $receipt.commit_before = (& git rev-parse HEAD).Trim()
    Say "clone at $($receipt.commit_before.Substring(0,7))"

    # -- carry the clone forward, offline -----------------------------------
    if (-not $SkipPull) {
      $bundle = Join-Path $Drop "workbench.bundle"
      if (-not (Test-Path -LiteralPath $bundle)) { throw "no bundle at '$bundle'" }

      # `verify` names the commit the bundle is built against. A thin bundle
      # applied to a clone that does not have it fails halfway with a less
      # obvious message, so it is checked first.
      & git bundle verify $bundle | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "the bundle does not apply to this clone" }

      & git fetch $bundle "main:refs/remotes/bundle/main"
      if ($LASTEXITCODE -ne 0) { throw "git fetch from the bundle failed" }

      # **`--ff-only`, deliberately.** This clone has carried hand-copied,
      # gitignored files before now, and a merge commit created here would be
      # a commit that exists only inside a VM that gets reverted. If it will
      # not fast-forward, that is a thing to look at rather than to resolve.
      & git merge --ff-only "refs/remotes/bundle/main"
      if ($LASTEXITCODE -ne 0) {
        throw ("the clone will not fast-forward. It has local commits or a " +
               "dirty tree; look before forcing anything.")
      }
      $receipt.pulled = $true
      Good "clone now at $((& git rev-parse HEAD).Trim().Substring(0,7))"
    }
    $receipt.commit_after = (& git rev-parse HEAD).Trim()

    # -- install the package into this guest's venv -------------------------
    $py = Join-Path $Repo ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $py)) {
      Warn "no .venv here; falling back to whatever 'python' resolves to"
      $py = "python"
    }

    if (-not $SkipInstall) {
      $wheels = Join-Path $Drop "wheels"
      if (-not (Test-Path -LiteralPath $wheels)) { throw "no wheels at '$wheels'" }
      Say "installing (offline, from $wheels)"
      & $py -m pip install --no-index --find-links $wheels -e . --no-deps
      if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
      $receipt.installed = $true
    }

    # -- prove it took ------------------------------------------------------
    # Read back through the same function the verdict envelope uses, rather
    # than through pip: what matters is what `analyzer_version()` answers, and
    # a successful install that the code cannot see is the failure worth
    # catching here.
    $probe = @'
import json
from verdict.provenance import analyzer_version, git_commit
print(json.dumps({"version": analyzer_version(), "commit": git_commit()}))
'@
    $out = $probe | & $py -
    if ($LASTEXITCODE -ne 0) { throw "could not import verdict.provenance" }
    $parsed = $out | ConvertFrom-Json
    $receipt.version = $parsed.version
    $receipt.commit_after = $parsed.commit

    if (-not $parsed.version) {
      throw ("analyzer_version() is still null. The install did not reach " +
             "the interpreter the analysis runs under.")
    }

    Good "version: $($parsed.version)"
    Good "commit : $($parsed.commit)"
    $receipt.ok = $true
  }
  finally { Pop-Location }
}
catch {
  $receipt.error = $_.Exception.Message
  Write-Host "[x] $($receipt.error)" -ForegroundColor Red
}

# The receipt goes back whatever happened -- a failure the host cannot see is
# the thing the agent's guest-local log was added to stop happening again.
try {
  if ($Drop -and (Test-Path -LiteralPath $Drop)) {
    $path = Join-Path $Drop "provision-receipt.json"
    ($receipt | ConvertTo-Json -Depth 4) |
      Set-Content -LiteralPath $path -Encoding utf8
    Say "receipt: $path"
  }
} catch { Warn "could not write the receipt: $($_.Exception.Message)" }

if ($receipt.ok) { exit 0 } else { exit 1 }
