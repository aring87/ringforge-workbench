<#
.SYNOPSIS
    Stand up a clean VM, install vendor software, and survey it for _ALWAYS_SIGNS.

.DESCRIPTION
    `deceptive_file_identity` accuses a binary of claiming a vendor it cannot be,
    and the list of vendors it will accuse over is derived from benign software
    rather than chosen. That derivation is bounded by one machine's installed
    software: Adobe, Avira, Opera and Windows Defender are all impersonated in
    the malware corpora and none qualifies, because none is installed on the
    analysis host at four samples or more.

    A bare installer does not fix that -- a vendor needs four binaries and an
    installer is one. Installed, each of these drops dozens of signed binaries
    carrying its CompanyName, which is what the derivation actually reads.

    This runs on a THROWAWAY VM, not the analysis guest. Avira is antivirus: on
    the guest it would quarantine the sample corpora and interfere with every
    detonation.

    Nothing sensitive leaves the VM. The survey writes one JSON of metadata --
    company names, signature subjects, section entropy -- and no binaries.

.NOTES
    **The silent-install flags below accept each vendor's licence agreement on
    your behalf.** They are also version-specific and go stale; if an installer
    opens a window instead of running quietly, install it by hand and re-run
    this with -SkipInstall.

.EXAMPLE
    .\bootstrap_vendor_survey.ps1 -Installers C:\installers
    .\bootstrap_vendor_survey.ps1 -SkipInstall
#>

[CmdletBinding()]
param(
    [string]$Installers = $PSScriptRoot,
    [string]$Repo = "https://github.com/aring87/ringforge-workbench.git",
    [string]$Work = "$env:USERPROFILE\vendor-survey",
    [string]$Out = "$env:USERPROFILE\benign-survey-vm.json",
    [int]$Count = 800,
    [int]$PerVendor = 12,
    [switch]$SkipInstall,
    [switch]$SkipClone
)

$ErrorActionPreference = "Stop"

function Step($text) { Write-Host "`n=== $text" -ForegroundColor Cyan }
function Note($text) { Write-Host "    $text" }

# Matched on filename because that is what a download leaves behind. Each entry
# is the vendor's own documented quiet switch; where a vendor documents none,
# the entry says so rather than guessing something that half-works.
$Silent = @(
    @{ Match = "Reader_*install*.exe"; Args = @("/sAll", "/rs", "/msi", "EULA_ACCEPT=YES"); Name = "Adobe Reader" },
    @{ Match = "OperaSetup*.exe";      Args = @("/silent", "/launchopera", "0", "/setdefaultbrowser", "0"); Name = "Opera" },
    @{ Match = "avira_*.exe";          Args = @("/S"); Name = "Avira" }
)

# --- preconditions ----------------------------------------------------------
Step "checking the machine"
foreach ($tool in @("git", "python")) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if (-not $found) { throw "$tool is not on PATH. Install it, then re-run." }
    Note "$tool -> $($found.Source)"
}

if ($env:COMPUTERNAME -and (Test-Path "C:\mal-bazaar-cases")) {
    throw ("This looks like the analysis guest: C:\mal-bazaar-cases exists. " +
           "Avira would quarantine the corpora. Run this on a throwaway VM.")
}

# --- install ----------------------------------------------------------------
if ($SkipInstall) {
    Step "skipping installs (-SkipInstall)"
} else {
    Step "installing vendor software from $Installers"
    Note "these flags accept each vendor's licence agreement"
    foreach ($entry in $Silent) {
        $files = @(Get-ChildItem -Path $Installers -Filter $entry.Match -ErrorAction SilentlyContinue)
        if ($files.Count -eq 0) { Note "$($entry.Name): no installer matching $($entry.Match)"; continue }
        foreach ($file in $files) {
            Note "$($entry.Name): $($file.Name)"
            try {
                $p = Start-Process -FilePath $file.FullName -ArgumentList $entry.Args -Wait -PassThru
                Note "   exit $($p.ExitCode)"
                if ($p.ExitCode -ne 0) {
                    Note "   non-zero: install it by hand, then re-run with -SkipInstall"
                }
            } catch {
                Note "   failed: $($_.Exception.Message)"
            }
        }
    }
    Note "letting installers settle"
    Start-Sleep -Seconds 20
}

# --- repo and venv ----------------------------------------------------------
if (-not $SkipClone) {
    Step "cloning $Repo"
    if (Test-Path $Work) {
        Note "$Work exists; pulling instead"
        Push-Location $Work; git pull; Pop-Location
    } else {
        git clone $Repo $Work
    }
}
if (-not (Test-Path $Work)) { throw "no working copy at $Work" }
Push-Location $Work

Step "creating the virtual environment"
# The survey needs pefile and nothing else: signature verification goes through
# PowerShell's Get-AuthenticodeSignature, not a Python library.
if (-not (Test-Path ".venv")) { python -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
.\.venv\Scripts\python.exe -m pip install --quiet pefile
Note "pefile installed"

# --- survey -----------------------------------------------------------------
Step "surveying installed software"
Note "this takes roughly a second per binary"
.\.venv\Scripts\python.exe scripts\benign_survey.py --out $Out --count $Count --per-vendor $PerVendor --workers 4

Pop-Location

Step "done"
Note "written: $Out"
Note ""
Note "Copy that one file back to the analysis host, then merge it:"
Note "    .venv\Scripts\python.exe scripts\derive_signers.py \"
Note "        --survey G:\benign-survey.json --survey <the copied file>"
Note ""
Note "A vendor qualifies on three measured facts: four or more samples, 95% of"
Note "them signed, and 95% of those signatures naming the vendor itself. The"
Note "third rule is why ffmpeg is not on the list, and it may exclude one of"
Note "these three as well -- an installer signed by a packaging partner has not"
Note "shown that its vendor signs."
