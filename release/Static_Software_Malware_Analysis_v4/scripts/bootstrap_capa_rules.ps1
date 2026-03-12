<#
.SYNOPSIS
  Downloads the latest capa-rules and installs them into tools\capa-rules\rules\

.DESCRIPTION
  Supports both capa-rules layouts:
    - Older: a top-level `rules/` directory
    - Newer: rule namespace folders at repo root (anti-analysis/, collection/, etc.)

  This script:
    1) Queries GitHub Releases API for the latest capa-rules release
    2) Downloads a release asset (.zip/.tgz) if present, otherwise falls back to GitHub zipball
    3) Extracts
    4) Detects the rules root
    5) Copies rules into: <repo_root>\tools\capa-rules\rules\

.PARAMETER Destination
  Destination base folder for capa rules. Default: <repo_root>\tools\capa-rules

.PARAMETER Repo
  GitHub repo for capa rules. Default: mandiant/capa-rules

.PARAMETER KeepTemp
  Keep temporary downloaded/extracted files (for debugging). Default: $false
#>

[CmdletBinding()]
param(
  [string]$Destination = "",
  [string]$Repo = "mandiant/capa-rules",
  [switch]$KeepTemp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

function Get-ScriptDir {
  if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }
  $inv = $MyInvocation.MyCommand.Path
  if ($inv -and $inv.Trim().Length -gt 0) { return (Split-Path -Parent $inv) }
  return (Get-Location).Path
}

function Expand-AnyArchive {
  param(
    [Parameter(Mandatory=$true)][string]$ArchivePath,
    [Parameter(Mandatory=$true)][string]$DestinationPath
  )
  $lower = $ArchivePath.ToLower()
  if ($lower.EndsWith(".zip")) {
    Expand-Archive -Path $ArchivePath -DestinationPath $DestinationPath -Force
    return
  }
  if ($lower.EndsWith(".tgz") -or $lower.EndsWith(".tar.gz")) {
    $tar = Get-Command tar -ErrorAction SilentlyContinue
    if (-not $tar) { throw "tar not found in PATH; cannot extract $ArchivePath" }
    New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
    & $tar.Source -xf $ArchivePath -C $DestinationPath
    return
  }
  throw "Unsupported archive type: $ArchivePath"
}

function Find-RulesRoot {
  param([Parameter(Mandatory=$true)][string]$ExtractPath)

  # 1) Prefer explicit rules/ folder
  $rulesDir = Get-ChildItem -Path $ExtractPath -Directory -Recurse -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -eq "rules" } | Select-Object -First 1
  if ($rulesDir) { return $rulesDir.FullName }

  # 2) Newer layout: rules live at repo root with namespace dirs
  $candidates = Get-ChildItem -Path $ExtractPath -Directory -Recurse -ErrorAction SilentlyContinue
  foreach ($dir in $candidates) {
    $readme = Join-Path $dir.FullName "README.md"
    if (-not (Test-Path -LiteralPath $readme)) { continue }

    $ns1 = Join-Path $dir.FullName "anti-analysis"
    $ns2 = Join-Path $dir.FullName "collection"
    $ns3 = Join-Path $dir.FullName "communication"
    if ((Test-Path -LiteralPath $ns1) -or (Test-Path -LiteralPath $ns2) -or (Test-Path -LiteralPath $ns3)) {
      return $dir.FullName
    }
  }

  # 3) Last resort: extracted root itself
  $rootReadme = Join-Path $ExtractPath "README.md"
  if (Test-Path -LiteralPath $rootReadme) {
    $ns1 = Join-Path $ExtractPath "anti-analysis"
    $ns2 = Join-Path $ExtractPath "collection"
    $ns3 = Join-Path $ExtractPath "communication"
    if ((Test-Path -LiteralPath $ns1) -or (Test-Path -LiteralPath $ns2) -or (Test-Path -LiteralPath $ns3)) {
      return $ExtractPath
    }
  }

  return $null
}

try {
  $scriptDir = Get-ScriptDir
  $repoRoot = Resolve-Path (Join-Path $scriptDir "..")

  if (-not $Destination -or $Destination.Trim().Length -eq 0) {
    $Destination = Join-Path $repoRoot "tools\capa-rules"
  }

  if (-not (Test-Path -LiteralPath $Destination)) {
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  }
  $destFull = (Resolve-Path -LiteralPath $Destination).Path

  Write-Info "Repo root: $($repoRoot.Path)"
  Write-Info "Destination: $destFull"
  Write-Info "Repo: $Repo"

  $headers = @{ "User-Agent" = "bootstrap_capa_rules.ps1" }

  Write-Info "Querying latest release..."
  $rel = Invoke-RestMethod -Headers $headers -Uri ("https://api.github.com/repos/{0}/releases/latest" -f $Repo)
  if (-not $rel -or -not $rel.tag_name) { throw "Failed to read latest release metadata." }

  Write-Info ("Latest release: {0}" -f $rel.tag_name)

  $tmpRoot = Join-Path $env:TEMP ("capa_rules_bootstrap_" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null

  $downloadUrl = $null
  $downloadName = $null

  $assets = @($rel.assets)
  if ($assets.Count -gt 0) {
    $candidate = @($assets | Where-Object { $_.name -match '\.(zip|tgz|tar\.gz)$' } | Select-Object -First 1)
    if ($candidate.Count -gt 0) {
      $downloadUrl = $candidate[0].browser_download_url
      $downloadName = $candidate[0].name
      Write-Info ("Using release asset: {0}" -f $downloadName)
    }
  }

  if (-not $downloadUrl) {
    $downloadUrl = $rel.zipball_url
    $downloadName = ("capa-rules-{0}-zipball.zip" -f $rel.tag_name)
    Write-Warn "No release assets found. Falling back to GitHub zipball source archive."
  }

  $tmpArchive = Join-Path $tmpRoot $downloadName
  $tmpExtract = Join-Path $tmpRoot ("extract_" + $rel.tag_name)

  Write-Info "Downloading..."
  Invoke-WebRequest -Headers $headers -Uri $downloadUrl -OutFile $tmpArchive

  Write-Info "Extracting..."
  Expand-AnyArchive -ArchivePath $tmpArchive -DestinationPath $tmpExtract

  Write-Info "Detecting rules root..."
  $rulesRoot = Find-RulesRoot -ExtractPath $tmpExtract
  if (-not $rulesRoot) {
    throw "Could not locate rules content in extracted archive. Inspect: $tmpExtract"
  }
  Write-Info ("Rules root: {0}" -f $rulesRoot)

  $targetRules = Join-Path $destFull "rules"

  if (Test-Path -LiteralPath $targetRules) {
    Write-Warn "Existing rules folder found. Replacing: $targetRules"
    Remove-Item -Recurse -Force -LiteralPath $targetRules
  }
  New-Item -ItemType Directory -Force -Path $targetRules | Out-Null

  Write-Info "Installing rules to: $targetRules"

  # IMPORTANT: use -Path for wildcard expansion (do NOT use -LiteralPath with '*')
  Copy-Item -Recurse -Force -Path (Join-Path $rulesRoot "*") -Destination $targetRules

  # Verification
  $ymlCount = (Get-ChildItem -Path $targetRules -File -Recurse -ErrorAction SilentlyContinue |
              Where-Object { $_.Extension -in @(".yml",".yaml") } |
              Measure-Object).Count
  $dirCount = (Get-ChildItem -Path $targetRules -Directory -ErrorAction SilentlyContinue | Measure-Object).Count

  if ($dirCount -eq 0) {
    Write-Warn "No directories copied into rules target. Something went wrong."
  }

  if ($ymlCount -lt 10) {
    Write-Warn "Installed rules count seems low ($ymlCount). Verify the directory contents."
  }

  Write-Ok ("Installed capa rules: {0} YAML files" -f $ymlCount)
  Write-Ok ("Path: {0}" -f $targetRules)
  Write-Ok ("Release: {0}" -f $rel.tag_name)

  if (-not $KeepTemp) {
    Remove-Item -Recurse -Force -LiteralPath $tmpRoot
  } else {
    Write-Warn ("Keeping temp folder: {0}" -f $tmpRoot)
  }

  Write-Ok "Done."
}
catch {
  Write-Host ""
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.ScriptStackTrace) {
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
  }
  exit 1
}
