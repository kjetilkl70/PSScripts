<#
.SYNOPSIS
    ProfileRemediation - Silent Rollback
    Automatically restores remediated profiles to pre-fix state.

.DESCRIPTION
    Runs as SYSTEM via Intune. No interactive prompts.

    Scans the completed\ directory for users that were remediated,
    imports the most recent registry backup for each, recreates the
    new SID ProfileList entry pointing to the .AD profile, and
    recreates the .AD folder if it was deleted.

    Designed to be deployed as an Intune Proactive Remediation (fix)
    or platform script when a rollback is needed across machines.

    Exit 0 = rollback completed or nothing to roll back.
    Exit 1 = error during rollback.

.PARAMETER UserName
    Optional. Roll back a specific user only. If not specified, all
    users with completion markers are rolled back.

.EXAMPLE
    .\Restore-ProfileRemediationSilent.ps1
    # Rolls back ALL remediated users on this machine

.EXAMPLE
    .\Restore-ProfileRemediationSilent.ps1 -UserName olsente4
    # Rolls back only olsente4

.NOTES
    Author:     Kjetil Klonteig
    Company:    Sopra Steria
    Version:    1.0.0
    Changelog:
        1.0.0 - Initial release. Silent SYSTEM rollback for Intune
                 deployment. Auto-discovers remediated users from
                 completion markers and registry backups.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$UserName
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = "1.0.0"

# ============================================================
# Configuration
# ============================================================
$DomainSuffix    = "AD"
$BaseDir         = "C:\ProgramData\ProfileRemediation"
$BackupDir       = Join-Path $BaseDir "Backup"
$CompletedDir    = Join-Path $BaseDir "completed"
$ProfileListReg  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

# ============================================================
# Event Log
# ============================================================
$EventSource  = "ProfileRemediation"
$EventLogName = "Application"
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try { New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction SilentlyContinue } catch { }
}

function Write-RestoreLog {
    param([string]$Message, [string]$Level = 'Information')
    Write-Output $Message
    try {
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId 3000 `
            -EntryType $Level -Message "[Restore v$ScriptVersion] $Message" -ErrorAction SilentlyContinue
    } catch { }
}

# ============================================================
# 1. Find users to roll back
# ============================================================
try {
    Write-RestoreLog "Starting silent rollback on $env:COMPUTERNAME"

    if (-not (Test-Path $CompletedDir)) {
        Write-RestoreLog "No completed directory found - nothing to roll back"
        exit 0
    }

    if ($UserName) {
        $MarkerFiles = Get-ChildItem -Path $CompletedDir -Filter "$UserName.done" -ErrorAction SilentlyContinue
    }
    else {
        $MarkerFiles = Get-ChildItem -Path $CompletedDir -Filter "*.done" -ErrorAction SilentlyContinue
    }

    if (-not $MarkerFiles -or $MarkerFiles.Count -eq 0) {
        Write-RestoreLog "No completion markers found - nothing to roll back"
        exit 0
    }

    Write-RestoreLog "Found $($MarkerFiles.Count) user(s) to roll back"

    $ErrorCount   = 0
    $SuccessCount = 0

    # ============================================================
    # 2. Process each user
    # ============================================================
    foreach ($Marker in $MarkerFiles) {
        $User = $Marker.BaseName  # filename without .done extension
        Write-RestoreLog "--- Processing rollback for: $User ---"

        try {
            # ---- Step 1: Find and import registry backup ----
            $UserBackups = Get-ChildItem -Path $BackupDir -Filter "$env:COMPUTERNAME-$User-*.reg" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending

            if (-not $UserBackups) {
                Write-RestoreLog "  WARNING: No registry backup found for $User - skipping"
                $ErrorCount++
                continue
            }

            $BackupFile = $UserBackups | Select-Object -First 1
            Write-RestoreLog "  Step 1/4: Importing backup $($BackupFile.Name)"
            $RegResult = & reg.exe import $BackupFile.FullName 2>&1
            Write-RestoreLog "  Step 1/4: reg.exe output: $RegResult"

            # Verify old SID was restored
            $UserProfileBase = "C:\Users\$User"
            $OldSidEntry = Get-ChildItem $ProfileListReg -ErrorAction SilentlyContinue | Where-Object {
                (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath -eq $UserProfileBase
            }

            if ($OldSidEntry) {
                Write-RestoreLog "  Step 1/4: Old SID restored: $($OldSidEntry.PSChildName) -> $UserProfileBase"
            }
            else {
                Write-RestoreLog "  Step 1/4: WARNING - Could not verify old SID restoration"
            }

            # ---- Step 2: Recreate new SID ProfileList entry ----
            Write-RestoreLog "  Step 2/4: Resolving current SID for $User"
            $UserProfileDuped = "C:\Users\$User.$DomainSuffix"
            $CurrentSid = $null

            $DomainFormats = @("$DomainSuffix\$User", "$env:USERDOMAIN\$User", "$User")
            foreach ($Format in $DomainFormats) {
                try {
                    $NtAccount = New-Object System.Security.Principal.NTAccount($Format)
                    $CurrentSid = $NtAccount.Translate(
                        [System.Security.Principal.SecurityIdentifier]).Value
                    Write-RestoreLog "  Step 2/4: Resolved SID for ${Format}: $CurrentSid"
                    break
                }
                catch { continue }
            }

            if (-not $CurrentSid) {
                Write-RestoreLog "  WARNING: Could not resolve SID for $User - skipping ProfileList entry"
            }
            else {
                $NewSidKeyPath = "$ProfileListReg\$CurrentSid"
                if (Test-Path $NewSidKeyPath) {
                    Set-ItemProperty -Path $NewSidKeyPath -Name "ProfileImagePath" -Value $UserProfileDuped
                    Write-RestoreLog "  Step 2/4: Updated existing entry: $CurrentSid -> $UserProfileDuped"
                }
                else {
                    New-Item -Path $NewSidKeyPath -Force | Out-Null
                    Set-ItemProperty -Path $NewSidKeyPath -Name "ProfileImagePath" -Value $UserProfileDuped -Type ExpandString
                    Set-ItemProperty -Path $NewSidKeyPath -Name "Flags" -Value 0 -Type DWord
                    Set-ItemProperty -Path $NewSidKeyPath -Name "State" -Value 0 -Type DWord
                    Write-RestoreLog "  Step 2/4: Created new entry: $CurrentSid -> $UserProfileDuped"
                }
            }

            # ---- Step 3: Recreate .AD folder if deleted ----
            if (Test-Path $UserProfileDuped) {
                Write-RestoreLog "  Step 3/4: $UserProfileDuped already exists"
            }
            else {
                New-Item -ItemType Directory -Path $UserProfileDuped -Force | Out-Null
                Write-RestoreLog "  Step 3/4: Recreated $UserProfileDuped"
            }

            # ---- Step 4: Remove markers and signal files ----
            $CleanupFiles = @(
                $Marker.FullName,
                (Join-Path $BaseDir "request-$User.json"),
                (Join-Path $BaseDir "signal-$User.flag")
            )
            foreach ($File in $CleanupFiles) {
                if (Test-Path $File) {
                    Remove-Item $File -Force -ErrorAction SilentlyContinue
                    Write-RestoreLog "  Step 4/4: Removed $(Split-Path $File -Leaf)"
                }
            }

            Write-RestoreLog "  Rollback completed for $User"
            $SuccessCount++
        }
        catch {
            Write-RestoreLog "  ERROR rolling back ${User}: $($_.Exception.Message)" -Level Error
            $ErrorCount++
        }
    }

    # ============================================================
    # 3. Summary
    # ============================================================
    Write-RestoreLog "Rollback complete: $SuccessCount succeeded, $ErrorCount failed"

    if ($ErrorCount -gt 0) {
        exit 1
    }
    exit 0
}
catch {
    Write-RestoreLog "CRITICAL ERROR: $($_.Exception.Message)" -Level Error
    exit 1
}
