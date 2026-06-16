<#
.SYNOPSIS
    Intune Remediation - Detection
    Sjekker om profilreparasjons-infrastrukturen er utrullet på maskinen.

.DESCRIPTION
    Kjøres i SYSTEM-kontekst på alle VDI-maskiner i scope.
    Verifiserer at scheduled tasks, logon-script og versjonsfil
    er korrekt installert.

    Returnerer exit 1 (remediation needed) hvis:
    - Versjonsfil mangler eller er utdatert
    - Script-filer mangler på disk
    - Scheduled tasks mangler

    Returnerer exit 0 hvis alt er på plass.

    Selve profildeteksjon og -reparasjon skjer per bruker ved logon
    via scheduled tasks — ikke her.

.NOTES
    Forfatter:  Kjetil Klonteig
    Firma:      Sopra Steria
    Versjon:    4.2.8
    Changelog:
        4.2.8 - Version bump for English translation.
        4.2.7 - Version bump for ASCII-fix, versjonsjekk og
                 konfigurerbare overlay-tekster.
        4.2.6 - Lagt til Launch-Engine.vbs i filsjekk.
        4.2.5 - Lagt til Launch-Overlay.vbs i filsjekk.
        4.2.4 - Versjonsbump for noedutgang i overlay.
        4.2.3 - Versjonsbump for variable-reference-fix.
        4.2.1 - Versjonsbump for XAML-fix og encoding-fix.
        4.2.0 - Versjonsbump for aa trigge reinstallasjon med ACL-fix.
        4.1.0 - Scheduled tasks flyttet til \ProfileRemediation\ i
                 Task Scheduler. Detect oppdatert med ny TaskPath.
        4.0.0 - Ny arkitektur: detect sjekker kun at infrastrukturen
                 er utrullet. Profildeteksjon skjer ved logon.
#>

$ErrorActionPreference = 'Stop'
$ScriptVersion = "4.2.8"

# ============================================================
# Konfigurasjon
# ============================================================
$BaseDir         = "C:\ProgramData\ProfileRemediation"
$VersionFile     = Join-Path $BaseDir "version.txt"
$OverlayScript   = Join-Path $BaseDir "Show-RemediationOverlay.ps1"
$OverlayLauncher = Join-Path $BaseDir "Launch-Overlay.vbs"
$EngineScript    = Join-Path $BaseDir "Invoke-ProfileRemediation.ps1"
$EngineLauncher  = Join-Path $BaseDir "Launch-Engine.vbs"
$TaskPath        = "\ProfileRemediation\"
$TaskNameOverlay = "ProfileRemediation-Overlay"
$TaskNameEngine  = "ProfileRemediation-Engine"

# ============================================================
# 1. Verifiser alle komponenter
# ============================================================
try {
    if (-not (Test-Path $VersionFile)) {
        Write-Output "INSTALL NEEDED: Versjonsfil mangler (v$ScriptVersion)"
        exit 1
    }

    $InstalledVersion = (Get-Content $VersionFile -ErrorAction Stop).Trim()
    if ([version]$InstalledVersion -lt [version]$ScriptVersion) {
        Write-Output "UPDATE NEEDED: Installert v$InstalledVersion, forventet v$ScriptVersion"
        exit 1
    }

    foreach ($File in @($OverlayScript, $OverlayLauncher, $EngineScript, $EngineLauncher)) {
        if (-not (Test-Path $File)) {
            Write-Output "INSTALL NEEDED: Mangler $(Split-Path $File -Leaf)"
            exit 1
        }
    }

    foreach ($TaskName in @($TaskNameOverlay, $TaskNameEngine)) {
        if (-not (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)) {
            Write-Output "INSTALL NEEDED: Scheduled task mangler: $TaskPath$TaskName"
            exit 1
        }
    }

    Write-Output "OK: ProfileRemediation v$InstalledVersion installert (v$ScriptVersion)"
    exit 0
}
catch {
    Write-Output "FEIL i detection: $($_.Exception.Message)"
    exit 0
}
