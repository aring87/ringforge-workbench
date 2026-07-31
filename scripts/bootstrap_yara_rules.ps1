<#
.SYNOPSIS
  Downloads a YARA ruleset and installs it into tools\yara\rules\

.DESCRIPTION
  Without rules, a memory dump is just a large file: the dynamic run writes it
  and reports "not scanned". This is the counterpart to bootstrap_capa_rules.ps1.

  Defaults to two rulesets, installed side by side, because their coverage is
  close to disjoint. Neo23x0/signature-base is strong on APT tooling, hacktools
  and webshells; elastic/protections-artifacts covers the commodity families --
  stealers, loaders, RATs -- that signature-base barely touches. Both are string-
  and memory-oriented rather than built on PE structure, which matters here:
  rules written against the `pe` module cannot match a raw process dump at all,
  so a PE-heavy ruleset produces confident-looking silence.

  Each set installs into its own subdirectory. Filenames collide across
  projects, and the directory a rule came from is the quickest way to find it
  again when it fires.

  Rules that fail to compile are moved to tools\yara\_broken rather than left to
  take the whole ruleset down with them -- yara.compile() is all-or-nothing
  across the files it is given, so one rule needing an unavailable module would
  otherwise mean zero scanning. The quarantine sits beside the rules directory,
  not inside it, because the scanner walks the rules directory recursively.

  Hand-maintained rules belong in tools\yara\local\. The rules directory itself
  is deleted and rebuilt on every run, so anything that must survive is sourced
  from there and copied back in afterwards -- that is what keeps the memory
  self-test rule in place across updates.

  This script:
    1) Downloads the repository archive
    2) Locates the directory holding .yar/.yara files
    3) Copies them into <repo_root>\tools\yara\rules\
    4) Copies tools\yara\local\ rules into <repo_root>\tools\yara\rules\local\
    5) Test-compiles the result and quarantines whatever fails

.PARAMETER Destination
  Destination base folder. Default: <repo_root>\tools\yara

.PARAMETER Repos
  GitHub repos to pull rules from, each installed into its own subdirectory of
  rules\. Defaults to both:

    Neo23x0/signature-base          APT, hacktools, webshells
    elastic/protections-artifacts   commodity malware families

  Two rather than one because they cover opposite halves of the problem, and
  the gap between them is not obvious until it costs a detonation.
  signature-base contains no AgentTesla rule at all, so a real AgentTesla
  sample produced an empty memory-only result that looked exactly like a
  broken pipeline -- the UPX control passing minutes later on the same VM was
  the only thing that distinguished them.

.PARAMETER Branch
  Branch to download when the repo publishes no releases. Default: master

.PARAMETER SkipCompileCheck
  Do not test-compile or quarantine. Faster, but a single broken rule can then
  silently disable all scanning.

.PARAMETER KeepTemp
  Keep temporary downloaded/extracted files (for debugging).
#>

[CmdletBinding()]
param(
  [string]$Destination = "",
  [string[]]$Repos = @("Neo23x0/signature-base", "elastic/protections-artifacts"),
  [string]$Branch = "master",
  [switch]$SkipCompileCheck,
  [switch]$KeepTemp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Step($msg) { Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Magenta }

function Get-ScriptDir {
  if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }
  $inv = $MyInvocation.MyCommand.Path
  if ($inv -and $inv.Trim().Length -gt 0) { return (Split-Path -Parent $inv) }
  return (Get-Location).Path
}

function Test-RuleCompilation {
  param(
    [Parameter(Mandatory=$true)][string]$RulesDir,
    [Parameter(Mandatory=$true)][string]$RepoRoot
  )

  $python = Get-Command python -ErrorAction SilentlyContinue
  if (-not $python) {
    Write-Warn "python not found in PATH; skipping the compile check."
    return
  }

  $checker = Join-Path $env:TEMP ("rf_yara_check_" + [Guid]::NewGuid().ToString("N") + ".py")

  # Quarantine OUTSIDE the rules directory. The scanner collects rule files by
  # walking the rules directory recursively, so a quarantine folder nested
  # inside it would hand the broken rules straight back to the next compile.
  $quarantine = Join-Path (Split-Path -Parent $RulesDir) "_broken"

  # Compile each file alone to find the bad ones, then move them aside. A single
  # file that needs an unavailable module fails the whole compile, so the
  # per-file pass is what makes the remainder usable.
  $lines = @(
    "import pathlib, shutil, sys",
    "try:",
    "    import yara",
    "except ImportError:",
    "    print('yara-python is not installed; cannot verify rules.')",
    "    sys.exit(3)",
    ("rules_dir = pathlib.Path(r'" + $RulesDir + "')"),
    ("quarantine = pathlib.Path(r'" + $quarantine + "')"),
    "externals = {'filename': '', 'filepath': '', 'extension': '', 'filetype': '', 'owner': '', 'md5': ''}",
    "broken = []",
    "ok = 0",
    "for path in sorted(rules_dir.rglob('*')):",
    "    if path.suffix.lower() not in {'.yar', '.yara'} or quarantine in path.parents:",
    "        continue",
    "    try:",
    "        yara.compile(filepath=str(path), externals=externals)",
    "        ok += 1",
    "    except Exception as error:",
    "        broken.append((path, str(error)))",
    "if broken:",
    "    quarantine.mkdir(parents=True, exist_ok=True)",
    "    for path, error in broken:",
    "        print('  quarantined %s: %s' % (path.name, str(error)[:120]))",
    "        try:",
    "            shutil.move(str(path), str(quarantine / path.name))",
    "        except Exception as move_error:",
    "            print('    could not move: %s' % move_error)",
    "print('%d rule file(s) compile; %d quarantined.' % (ok, len(broken)))",
    "if ok == 0:",
    "    sys.exit(2)",
    "try:",
    "    files = {}",
    "    for index, path in enumerate(sorted(rules_dir.rglob('*'))):",
    "        if path.suffix.lower() in {'.yar', '.yara'} and quarantine not in path.parents:",
    "            files['r%d' % index] = str(path)",
    "    yara.compile(filepaths=files, externals=externals)",
    "    print('Combined compile of %d file(s) succeeded.' % len(files))",
    "except Exception as error:",
    "    print('Combined compile still fails: %s' % error)",
    "    sys.exit(2)",
    "sys.exit(0)"
  )

  Set-Content -LiteralPath $checker -Value $lines -Encoding utf8

  try {
    & $python.Source $checker
    $code = $LASTEXITCODE
    if ($code -eq 0) {
      Write-Ok "Ruleset compiles."
    } elseif ($code -eq 3) {
      Write-Warn "Could not verify: install yara-python with 'pip install -r requirements.txt'."
    } else {
      Write-Warn "The ruleset does not compile cleanly. Memory scanning may report an error."
    }
  } finally {
    Remove-Item -LiteralPath $checker -Force -ErrorAction SilentlyContinue
  }
}

function Install-RuleSet {
  <#
    Downloads one ruleset into its own subdirectory of rules\.

    Each set gets its own folder rather than being flattened together, for two
    reasons. Rule filenames collide across projects, and a flat copy would let
    one project silently overwrite another's rules. And when a rule fires, the
    directory it came from is the fastest way to know which project to go and
    read it in.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Repo,
    [Parameter(Mandatory=$true)][string]$Branch,
    [Parameter(Mandatory=$true)][string]$RulesRoot,
    [Parameter(Mandatory=$true)][string]$TmpRoot,
    [Parameter(Mandatory=$true)][hashtable]$Headers
  )

  Write-Step ("Ruleset: {0}" -f $Repo)

  $slug = ($Repo -replace '[\/]', '-').ToLower()
  $target = Join-Path $RulesRoot $slug

  $downloadUrl = $null
  $label = ""

  try {
    $rel = Invoke-RestMethod -Headers $Headers -Uri ("https://api.github.com/repos/{0}/releases/latest" -f $Repo)
    if ($rel -and $rel.zipball_url) {
      $downloadUrl = $rel.zipball_url
      $label = $rel.tag_name
      Write-Info ("Latest release: {0}" -f $label)
    }
  } catch {
    Write-Info "No published releases; using the branch archive instead."
  }

  if (-not $downloadUrl) {
    $downloadUrl = "https://github.com/$Repo/archive/refs/heads/$Branch.zip"
    $label = $Branch
  }

  $tmpArchive = Join-Path $TmpRoot ("{0}.zip" -f $slug)

  Write-Info "Downloading..."
  try {
    Invoke-WebRequest -Headers $Headers -Uri $downloadUrl -OutFile $tmpArchive
  } catch {
    # One ruleset failing must not cost the others. A run with signature-base
    # and without Elastic is far better than no rules at all.
    Write-Warn ("Download failed for {0}: {1}" -f $Repo, $_.Exception.Message)
    return 0
  }

  # Only .yar/.yara entries are extracted, straight into the destination,
  # rather than expanding the whole archive and then copying.
  #
  # This is not just tidier. Expand-Archive on elastic/protections-artifacts
  # fails outright: it also ships behavior rules as .toml under
  # behavior\rules\cross-platform\ with names like
  # credential_access_potential_credential_validation_via_sudo_from_unusual_parent.toml,
  # and a temp path plus those blows past the 260-character MAX_PATH limit
  # mid-extraction. Nothing here wants those files anyway.
  Write-Info "Extracting rule files..."
  New-Item -ItemType Directory -Force -Path $target | Out-Null
  Add-Type -AssemblyName System.IO.Compression.FileSystem

  $count = 0
  try {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($tmpArchive)
    try {
      foreach ($entry in $zip.Entries) {
        if ($entry.Name -notmatch '\.(yar|yara)$') { continue }

        $dest = Join-Path $target $entry.Name
        if (Test-Path -LiteralPath $dest) {
          # Same filename in two directories of one archive. Keep both rather
          # than letting the second silently replace the first.
          $dest = Join-Path $target ("{0}__{1}" -f $count, $entry.Name)
        }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        $count++
      }
    } finally {
      $zip.Dispose()
    }
  } catch {
    Write-Warn ("Extraction failed for {0}: {1}" -f $Repo, $_.Exception.Message)
    return 0
  }

  if ($count -eq 0) {
    Write-Warn ("No .yar or .yara files found in {0}; skipping." -f $Repo)
    return 0
  }

  Write-Ok ("{0} rule file(s) from {1} ({2}) -> rules\{3}" -f $count, $Repo, $label, $slug)
  return $count
}


try {
  $scriptDir = Get-ScriptDir
  $repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path

  if (-not $Destination -or $Destination.Trim().Length -eq 0) {
    $Destination = Join-Path $repoRoot "tools\yara"
  }

  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  $destFull = (Resolve-Path -LiteralPath $Destination).Path

  Write-Info "Repo root: $repoRoot"
  Write-Info "Destination: $destFull"
  Write-Info ("Rulesets: {0}" -f ($Repos -join ", "))

  $headers = @{ "User-Agent" = "bootstrap_yara_rules.ps1" }

  $tmpRoot = Join-Path $env:TEMP ("yara_rules_bootstrap_" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null

  # Staged, then swapped in only once something actually downloaded.
  #
  # Deleting the live rules folder first and rebuilding in place means any
  # failure -- a network blip, an archive that will not extract, a typo in this
  # script -- leaves the guest with no rules at all, which is strictly worse
  # than not having run the script. That happened twice in one session, and the
  # second time the run afterwards would have scanned nothing and reported it
  # as a clean result.
  $targetRules = Join-Path $destFull "rules"
  $stagingRules = Join-Path $destFull "rules.staging"

  if (Test-Path -LiteralPath $stagingRules) {
    Remove-Item -Recurse -Force -LiteralPath $stagingRules
  }
  New-Item -ItemType Directory -Force -Path $stagingRules | Out-Null

  $totalRules = 0
  foreach ($repoName in $Repos) {
    $totalRules += Install-RuleSet -Repo $repoName -Branch $Branch `
                                   -RulesRoot $stagingRules -TmpRoot $tmpRoot -Headers $headers
  }

  if ($totalRules -eq 0) {
    Remove-Item -Recurse -Force -LiteralPath $stagingRules -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $targetRules) {
      Write-Warn "Nothing downloaded. The existing ruleset has been left untouched."
    }
    throw "No rule files were installed from any ruleset. Inspect: $tmpRoot"
  }

  Write-Host ""
  Write-Ok ("{0} rule file(s) installed across {1} ruleset(s)." -f $totalRules, $Repos.Count)

  # Hand-maintained rules live outside the downloaded set and are copied in
  # afterwards. Nothing inside rules\ is precious -- it is deleted and rebuilt on
  # every run -- so anything that must survive has to be sourced from elsewhere.
  $localSource = Join-Path $destFull "local"
  if (Test-Path -LiteralPath $localSource) {
    $localFiles = @(Get-ChildItem -Path $localSource -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in @(".yar", ".yara") })
    if ($localFiles.Count -gt 0) {
      # A subdirectory rather than the rules root, so a local filename can never
      # silently overwrite a downloaded rule of the same name.
      $localTarget = Join-Path $stagingRules "local"
      New-Item -ItemType Directory -Force -Path $localTarget | Out-Null
      foreach ($file in $localFiles) {
        Copy-Item -LiteralPath $file.FullName -Destination $localTarget -Force
      }
      Write-Ok ("Installed {0} local rule file(s) from {1}" -f $localFiles.Count, $localSource)
    }
  } else {
    Write-Info "No tools\yara\local directory; skipping local rules."
  }

  # Swap only now, when the staged tree is known to hold rules.
  if (Test-Path -LiteralPath $targetRules) {
    Remove-Item -Recurse -Force -LiteralPath $targetRules
  }
  Move-Item -LiteralPath $stagingRules -Destination $targetRules
  Write-Ok ("Ruleset installed at {0}" -f $targetRules)

  if (-not $SkipCompileCheck) {
    Write-Info "Test-compiling the ruleset..."
    Test-RuleCompilation -RulesDir $targetRules -RepoRoot $repoRoot
  }

  if (-not $KeepTemp) {
    Remove-Item -Recurse -Force -LiteralPath $tmpRoot -ErrorAction SilentlyContinue
  } else {
    Write-Warn ("Keeping temp folder: {0}" -f $tmpRoot)
  }

  Write-Host ""
  Write-Ok "Done. The Dynamic Analysis window should now report 'Mem YARA: ready'."
}
catch {
  Write-Host ""
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.ScriptStackTrace) {
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
  }
  exit 1
}
