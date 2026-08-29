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
    .\bootstrap_vendor_survey.ps1 -Installers C:\installers -Force
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
    [switch]$SkipClone,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Step($text) { Write-Host "`n=== $text" -ForegroundColor Cyan }
function Note($text) { Write-Host "    $text" }

# Matched on filename because that is what a download leaves behind. Each entry
# is the vendor's own documented quiet switch; where a vendor documents none,
# the entry says so rather than guessing something that half-works.
#
# `Installed` is the DisplayName pattern to look for before running anything.
# `Vendor` is the CompanyName the survey will actually read, which is not always
# the installer's: OperaSetup.exe is a 7-Zip self-extracting archive and reports
# `Igor Pavlov`, so surveying the installer would add a spurious sample to a
# different vendor rather than add Opera at all.
$Silent = @(
    @{ Match = "Reader_*install*.exe"; Args = @("/sAll", "/rs", "/msi", "EULA_ACCEPT=YES");
       Name = "Adobe Reader"; Installed = "Adobe Acrobat*"; Vendor = "Adobe Inc" },
    @{ Match = "OperaSetup*.exe";      Args = @("/silent", "/launchopera", "0", "/setdefaultbrowser", "0");
       Name = "Opera"; Installed = "Opera*"; Vendor = "Opera Norway AS" },
    @{ Match = "avira_*.exe";          Args = @("/S");
       Name = "Avira"; Installed = "Avira*"; Vendor = "Avira Operations GmbH" }
)

# **Ask the machine, not the filesystem.** A vendor folder under Program Files
# survives an uninstall often enough to be a bad signal; the uninstall registry
# is what Windows itself considers installed. Both 64- and 32-bit views, and the
# per-user hive, because these three install into different ones.
$UninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

function Get-InstalledNames {
    $names = @()
    foreach ($key in $UninstallKeys) {
        try {
            $names += Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
                      Where-Object { $_.DisplayName } |
                      Select-Object -ExpandProperty DisplayName
        } catch { }
    }
    return $names
}

function Test-Installed($pattern, $names) {
    foreach ($n in $names) { if ($n -like $pattern) { return $n } }
    return $null
}

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
    $installedNames = Get-InstalledNames
    Note "$($installedNames.Count) products already registered on this machine"
    foreach ($entry in $Silent) {
        $already = Test-Installed $entry.Installed $installedNames
        if ($already -and -not $Force) {
            Note "$($entry.Name): already installed as '$already' -- skipping"
            continue
        }
        $files = @(Get-ChildItem -Path $Installers -Filter $entry.Match -ErrorAction SilentlyContinue)
        if ($files.Count -eq 0) {
            if ($already) { Note "$($entry.Name): already installed; no installer to re-run" }
            else { Note "$($entry.Name): NOT installed and no installer matching $($entry.Match)" }
            continue
        }
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

    # **Say plainly which vendors the survey can and cannot speak for.** A
    # vendor that did not install is not a vendor the derivation will fail to
    # add quietly -- it is one the run cannot answer for, and that is worth
    # knowing before the JSON is carried back rather than after.
    Step "checking what actually installed"
    $installedNames = Get-InstalledNames
    foreach ($entry in $Silent) {
        $already = Test-Installed $entry.Installed $installedNames
        if ($already) { Note "OK      $($entry.Name) -> '$already'" }
        else { Note "MISSING $($entry.Name) -- the survey will not add $($entry.Vendor)" }
    }
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
$surveyExit = $LASTEXITCODE

Pop-Location

# **PowerShell does not throw when a native executable fails**, and the first
# version of this script printed "done -- written: <path>" over a survey that
# had never written anything. Reporting success without looking is the exact
# failure this project keeps finding in its own collectors, and a wrapper is
# not exempt from it.
if ($surveyExit -ne 0) {
    throw ("the survey exited $surveyExit and wrote nothing. Run it in the " +
           "foreground to see why: cd $Work then " +
           ".\.venv\Scripts\python.exe scripts\benign_survey.py --out $Out")
}
if (-not (Test-Path $Out)) {
    throw ("the survey reported success but $Out does not exist. Run it in " +
           "the foreground.")
}
$sizeKb = [math]::Round((Get-Item $Out).Length / 1KB)
Step "done"
Note "written: $Out  ($sizeKb KB)"
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
