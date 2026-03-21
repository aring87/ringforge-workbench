[CmdletBinding()]
param(
    [string]$RepoRoot = (Get-Location).Path,
    [string]$NewLocalRoot = "",
    [switch]$WhatIfOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

function Replace-InFile {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [hashtable]$Replacements
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warn "File not found, skipping: $Path"
        return
    }

    $content = Get-Content -LiteralPath $Path -Raw
    $original = $content

    foreach ($key in $Replacements.Keys) {
        $content = $content -replace [regex]::Escape($key), $Replacements[$key]
    }

    if ($content -ne $original) {
        if ($WhatIfOnly) {
            Write-Info "Would update: $Path"
        } else {
            Set-Content -LiteralPath $Path -Value $content -Encoding UTF8
            Write-Ok "Updated: $Path"
        }
    } else {
        Write-Info "No changes needed: $Path"
    }
}

function Rename-IfExists {
    param(
        [Parameter(Mandatory)] [string]$OldPath,
        [Parameter(Mandatory)] [string]$NewPath
    )

    if (-not (Test-Path -LiteralPath $OldPath)) {
        Write-Warn "Path not found, skipping rename: $OldPath"
        return
    }

    if (Test-Path -LiteralPath $NewPath) {
        Write-Warn "Target already exists, skipping rename: $NewPath"
        return
    }

    if ($WhatIfOnly) {
        Write-Info "Would rename: $OldPath -> $NewPath"
    } else {
        Rename-Item -LiteralPath $OldPath -NewName ([System.IO.Path]::GetFileName($NewPath))
        Write-Ok "Renamed: $OldPath -> $NewPath"
    }
}

$RepoRoot = (Resolve-Path $RepoRoot).Path
Set-Location $RepoRoot

Write-Info "Repo root: $RepoRoot"

$readmePath        = Join-Path $RepoRoot "README.md"
$guiPath           = Join-Path $RepoRoot "scripts\static_triage_gui.py"
$specOldPath       = Join-Path $RepoRoot "RingForgeAnalyzer.spec"
$specNewPath       = Join-Path $RepoRoot "RingForgeWorkbench.spec"
$releaseReadmePath = Join-Path $RepoRoot "release\RingForge_Analyzer_v1.2\README.txt"
$releaseOldDir     = Join-Path $RepoRoot "release\RingForge_Analyzer_v1.2"
$releaseNewDir     = Join-Path $RepoRoot "release\RingForge_Workbench_v1.2"
$configPath        = Join-Path $RepoRoot "config.json"

$readmeReplacements = [ordered]@{
    "# RingForge Workbench - Static and Dynamic Software Analysis Platform" = "# RingForge Workbench - Static, Dynamic, and Behavioral Software Triage Platform"
    "RingForge Analyzer is designed to help analysts quickly triage Windows software samples" = "RingForge Workbench is designed to help analysts quickly triage Windows software samples"
    "RingForge Analyzer v1.2 builds on the v1.1 scoring and workflow milestone" = "RingForge Workbench v1.2 builds on the v1.1 scoring and workflow milestone"
    "RingForge-Analyzer/" = "ringforge-workbench/"
    "RingForge_Analyzer_v1.1/" = "RingForge_Workbench_v1.2/"
    "RingForgeAnalyzer.exe" = "RingForgeWorkbench.exe"
    "RingForge Analyzer is being expanded from a static triage utility into a more complete multi-stage software analysis platform." = "RingForge Workbench is being expanded from a static triage utility into a more complete multi-stage software analysis platform."
    "The long-term goal is to evolve RingForge Analyzer into a unified triage platform" = "The long-term goal is to evolve RingForge Workbench into a unified triage platform"
    "cd ~/analysis/RingForge-Analyzer" = "cd ~/analysis/ringforge-workbench"
    "## Packaging RingForge Analyzer v1.1" = "## Packaging RingForge Workbench v1.2"
    "pyinstaller --onedir --windowed --name RingForgeAnalyzer --paths . --collect-submodules dynamic_analysis scripts/static_triage_gui_v10.py" = "pyinstaller --onedir --windowed --name RingForgeWorkbench --paths . --collect-submodules dynamic_analysis scripts/static_triage_gui_v10.py"
    "Compress-Archive -Path .\RingForge_Analyzer_v1.1 -DestinationPath .\RingForge_Analyzer_v1.1.zip -Force" = "Compress-Archive -Path .\RingForge_Workbench_v1.2 -DestinationPath .\RingForge_Workbench_v1.2.zip -Force"
    "## Release Notes - RingForge Analyzer v1.1" = "## Release Notes - RingForge Workbench v1.2"
    "dynamic analysis in RingForge Analyzer v1.1 is intended as a practical triage layer, not a full sandbox replacement" = "dynamic analysis in RingForge Workbench v1.2 is intended as a practical triage layer, not a full sandbox replacement"
    "RingForge Analyzer" = "RingForge Workbench"
}

$guiReplacements = [ordered]@{
    'return {"User-Agent": "RingForge-Analyzer/1.0"}' = 'return {"User-Agent": "RingForge-Workbench/1.2"}'
}

$releaseReadmeReplacements = [ordered]@{
    "RingForge Analyzer v1.2" = "RingForge Workbench v1.2"
    "RingForgeAnalyzer.exe" = "RingForgeWorkbench.exe"
}

$specReplacements = [ordered]@{
    "name='RingForgeAnalyzer'" = "name='RingForgeWorkbench'"
    "RingForgeAnalyzer" = "RingForgeWorkbench"
}

Write-Info "Updating active project files..."
Replace-InFile -Path $readmePath        -Replacements $readmeReplacements
Replace-InFile -Path $guiPath           -Replacements $guiReplacements
Replace-InFile -Path $releaseReadmePath -Replacements $releaseReadmeReplacements
Replace-InFile -Path $specOldPath       -Replacements $specReplacements

Write-Info "Renaming active packaging artifacts..."
Rename-IfExists -OldPath $specOldPath   -NewPath $specNewPath
Rename-IfExists -OldPath $releaseOldDir -NewPath $releaseNewDir

if ($NewLocalRoot -and (Test-Path -LiteralPath $configPath)) {
    Write-Info "Updating config.json local paths..."
    $configReplacements = [ordered]@{
        "C:\RingForge_Analyzer\Static-Software-Malware-Analysis\cases" = "$NewLocalRoot\cases"
        "C:\RingForge_Analyzer\Static-Software-Malware-Analysis\tools\capa-rules" = "$NewLocalRoot\tools\capa-rules"
        "C:\RingForge_Analyzer\Static-Software-Malware-Analysis\tools\capa\sigs" = "$NewLocalRoot\tools\capa\sigs"
        "C:\RingForge_Analyzer\Static-Software-Malware-Analysis\cases\whoami_full_final" = "$NewLocalRoot\cases\whoami_full_final"
        "C:\RingForge_Analyzer\Static-Software-Malware-Analysis\tools\procmon-configs\dynamic_default.pmc" = "$NewLocalRoot\tools\procmon-configs\dynamic_default.pmc"
    }
    Replace-InFile -Path $configPath -Replacements $configReplacements
}
elseif (Test-Path -LiteralPath $configPath) {
    Write-Warn "config.json was not changed. Set -NewLocalRoot if you want those paths updated."
}

Write-Info "Done."
Write-Host ""
Write-Host "Run these next:" -ForegroundColor Magenta
Write-Host "git status"
Write-Host 'Get-ChildItem -Recurse -File -Include *.py,*.md,*.txt,*.json,*.spec | Where-Object { $_.FullName -notmatch "\\.venv\\|\\build\\|\\dist\\|\\__pycache__\\|\\release\\RingForge_Analyzer_v1\\|\\release\\RingForge_Analyzer_v1.1\\|\\release\\v5\\" } | Select-String "RingForge Analyzer|RingForgeAnalyzer|RingForge-Analyzer"'