<#
.SYNOPSIS
    ProfileRemediation - ACL Fix
    Applies correct NTFS permissions to profiles that were remediated
    before Step 5 (ACL update) was added in v4.3.0.

.DESCRIPTION
    Runs as SYSTEM via Intune. No interactive prompts.

    Scans the completed\ directory for users that were successfully
    remediated (markers starting with "OK:"), resolves each user's
    current SID, and applies ownership + Full Control to their
    original profile folder. Removes the old SID from ACLs.

    Safe to run on machines already running v4.3.0 - the ACL
    operations are idempotent.

    Exit 0 = ACLs updated or nothing to update.
    Exit 1 = error during ACL update.

.PARAMETER UserName
    Optional. Fix ACLs for a specific user only. If not specified,
    all users with completion markers are processed.

.EXAMPLE
    .\Fix-ProfileACL.ps1
    # Fixes ACLs for ALL remediated users on this machine

.EXAMPLE
    .\Fix-ProfileACL.ps1 -UserName olsente4
    # Fixes ACLs only for olsente4

.NOTES
    Author:     Kjetil Klonteig
    Company:    Sopra Steria
    Version:    1.0.0
    Changelog:
        1.0.0 - Initial release. Retroactive ACL fix for profiles
                 remediated before v4.3.0 added Step 5.
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
$DomainSuffix   = "AD"
$BaseDir        = "C:\ProgramData\ProfileRemediation"
$CompletedDir   = Join-Path $BaseDir "completed"
$LogDir         = Join-Path $BaseDir "logs"

# ============================================================
# Event Log
# ============================================================
$EventSource  = "ProfileRemediation"
$EventLogName = "Application"
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try { New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction SilentlyContinue } catch { }
}

function Write-ACLLog {
    param([string]$Message, [string]$Level = 'Information')
    Write-Output $Message
    # File log
    $LogFile = Join-Path $LogDir "acl-fix.log"
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    Add-Content -Path $LogFile -Value "$Timestamp [ACL-Fix] $Message" -ErrorAction SilentlyContinue
    # Event log
    try {
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId 4000 `
            -EntryType $Level -Message "[ACL-Fix v$ScriptVersion] $Message" -ErrorAction SilentlyContinue
    } catch { }
}

# ============================================================
# 1. Find remediated users
# ============================================================
try {
    Write-ACLLog "Starting ACL fix on $env:COMPUTERNAME"

    if (-not (Test-Path $CompletedDir)) {
        Write-ACLLog "No completed directory found - nothing to fix"
        exit 0
    }

    if ($UserName) {
        $MarkerFiles = Get-ChildItem -Path $CompletedDir -Filter "$UserName.done" -ErrorAction SilentlyContinue
    }
    else {
        $MarkerFiles = Get-ChildItem -Path $CompletedDir -Filter "*.done" -ErrorAction SilentlyContinue
    }

    if (-not $MarkerFiles -or $MarkerFiles.Count -eq 0) {
        Write-ACLLog "No completion markers found - nothing to fix"
        exit 0
    }

    # Only process markers that indicate a successful remediation (start with "OK:")
    $UsersToFix = @()
    foreach ($Marker in $MarkerFiles) {
        $Content = (Get-Content $Marker.FullName -ErrorAction SilentlyContinue)
        if ($Content -match '^OK:') {
            $UsersToFix += $Marker
        }
        else {
            Write-ACLLog "Skipping $($Marker.BaseName) - marker is '$Content' (not a remediated user)"
        }
    }

    if ($UsersToFix.Count -eq 0) {
        Write-ACLLog "No successfully remediated users found - nothing to fix"
        exit 0
    }

    Write-ACLLog "Found $($UsersToFix.Count) remediated user(s) to process"

    $ErrorCount   = 0
    $SuccessCount = 0

    # ============================================================
    # 2. Fix ACLs for each user
    # ============================================================
    foreach ($Marker in $UsersToFix) {
        $User = $Marker.BaseName
        $UserProfileBase = "C:\Users\$User"

        Write-ACLLog "--- Processing: $User ---"

        try {
            # Verify profile folder exists
            if (-not (Test-Path $UserProfileBase)) {
                Write-ACLLog "  WARNING: Profile folder $UserProfileBase does not exist - skipping"
                $ErrorCount++
                continue
            }

            # Parse old and new SID from completion marker (format: OK:oldSID->newSID:timestamp)
            $MarkerContent = Get-Content $Marker.FullName -ErrorAction SilentlyContinue
            $OldSid = $null
            $NewSid = $null

            if ($MarkerContent -match '^OK:(S-1-5-[\d-]+)->(S-1-5-[\d-]+):') {
                $OldSid = $Matches[1]
                $NewSid = $Matches[2]
                Write-ACLLog "  SIDs from marker: old=$OldSid, new=$NewSid"
            }
            else {
                # Fallback: resolve SID from AD
                Write-ACLLog "  Could not parse SIDs from marker, resolving from AD"
                $DomainFormats = @("$DomainSuffix\$User", "$env:USERDOMAIN\$User", "$User")
                foreach ($Format in $DomainFormats) {
                    try {
                        $NtAccount = New-Object System.Security.Principal.NTAccount($Format)
                        $NewSid = $NtAccount.Translate(
                            [System.Security.Principal.SecurityIdentifier]).Value
                        Write-ACLLog "  Resolved SID for ${Format}: $NewSid"
                        break
                    }
                    catch { continue }
                }

                if (-not $NewSid) {
                    Write-ACLLog "  ERROR: Could not resolve SID for $User - skipping" -Level Error
                    $ErrorCount++
                    continue
                }
            }

            # ---- Take ownership ----
            Write-ACLLog "  Taking ownership of $UserProfileBase"
            $TakeownResult = & takeown.exe /F $UserProfileBase /R /A /D Y 2>&1
            $TakeownLast = ($TakeownResult | Select-Object -Last 1) -as [string]
            Write-ACLLog "  takeown completed: $TakeownLast"

            # ---- Grant Full Control to new SID ----
            Write-ACLLog "  Granting Full Control to $NewSid"
            $IcaclsGrant = & icacls.exe $UserProfileBase /grant "*${NewSid}:(OI)(CI)F" /T /C /Q 2>&1
            $IcaclsLast = ($IcaclsGrant | Select-Object -Last 1) -as [string]
            Write-ACLLog "  icacls grant completed: $IcaclsLast"

            # ---- Set new SID as owner ----
            Write-ACLLog "  Setting $NewSid as owner"
            $IcaclsOwner = & icacls.exe $UserProfileBase /setowner "*$NewSid" /T /C /Q 2>&1
            $IcaclsOwnerLast = ($IcaclsOwner | Select-Object -Last 1) -as [string]
            Write-ACLLog "  icacls setowner completed: $IcaclsOwnerLast"

            # ---- Remove old SID from ACLs (if known) ----
            if ($OldSid) {
                Write-ACLLog "  Removing old SID $OldSid from ACLs"
                $IcaclsRemove = & icacls.exe $UserProfileBase /remove "*$OldSid" /T /C /Q 2>&1
                $IcaclsRemoveLast = ($IcaclsRemove | Select-Object -Last 1) -as [string]
                Write-ACLLog "  icacls remove completed: $IcaclsRemoveLast"
            }
            else {
                Write-ACLLog "  Old SID unknown - skipping ACL removal (non-critical)"
            }

            Write-ACLLog "  ACL fix completed for $User"
            $SuccessCount++
        }
        catch {
            Write-ACLLog "  ERROR fixing ACLs for ${User}: $($_.Exception.Message)" -Level Error
            $ErrorCount++
        }
    }

    # ============================================================
    # 3. Summary
    # ============================================================
    Write-ACLLog "ACL fix complete: $SuccessCount succeeded, $ErrorCount failed"

    if ($ErrorCount -gt 0) {
        exit 1
    }
    exit 0
}
catch {
    Write-ACLLog "CRITICAL ERROR: $($_.Exception.Message)" -Level Error
    exit 1
}
