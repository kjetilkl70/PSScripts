<#
.SYNOPSIS
    ProfileRemediation - On-Demand Fix
    Standalone script for engineers to run as local admin.
    Detects and fixes duplicate profiles in a single run.

.DESCRIPTION
    Run from an elevated (Administrator) PowerShell prompt.
    No installation, no scheduled tasks - just run and done.

    The script:
    1. Auto-detects users with duplicate .AD profiles (or use -UserName)
    2. Backs up the old ProfileList registry key
    3. Remaps ProfileList so the new SID points to the original profile
    4. Removes the empty .AD profile folder
    5. Updates NTFS ownership and permissions on the profile folder
    6. Shows a popup telling the user to log off

.PARAMETER UserName
    Optional. Fix a specific user. If not specified, the script
    auto-detects all users with duplicate profiles on this machine.

.PARAMETER DomainSuffix
    NETBIOS name of the new domain. Default: "AD"

.EXAMPLE
    .\Invoke-ProfileFix.ps1
    # Auto-detects and fixes all duplicate profiles

.EXAMPLE
    .\Invoke-ProfileFix.ps1 -UserName olsente4
    # Fixes only olsente4

.NOTES
    Author:     Kjetil Klonteig
    Company:    Sopra Steria
    Version:    1.0.0
    Changelog:
        1.0.0 - Initial release. Standalone on-demand script for
                 engineers. Auto-detection, registry remap, ACL fix,
                 and user notification in a single run.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$UserName,

    [Parameter(Mandatory = $false)]
    [string]$DomainSuffix = "AD"
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = "1.0.0"

# ============================================================
# Configuration
# ============================================================
$BackupDir      = "C:\ProgramData\ProfileRemediation\Backup"
$LogFile        = "C:\ProgramData\ProfileRemediation\logs\ondemand-fix.log"
$ProfileListReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$Timestamp] $Message" -ForegroundColor $Color

    $LogDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value "$Timestamp $Message" -ErrorAction SilentlyContinue
}

# ============================================================
# 1. Check elevation
# ============================================================
Write-Host "`nProfileRemediation On-Demand Fix v$ScriptVersion" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan

$Principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`nERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'.`n" -ForegroundColor Yellow
    exit 1
}

# ============================================================
# 2. Find users with duplicate profiles
# ============================================================
Write-Log "Scanning for duplicate profiles (suffix: .$DomainSuffix)" "Cyan"

$UsersToFix = @()

if ($UserName) {
    # Specific user requested
    $ProfileBase  = "C:\Users\$UserName"
    $ProfileDuped = "C:\Users\$UserName.$DomainSuffix"

    if (-not (Test-Path $ProfileDuped)) {
        Write-Log "No duplicate found: $ProfileDuped does not exist" "Yellow"
        exit 0
    }
    if (-not (Test-Path $ProfileBase)) {
        Write-Log "No original found: $ProfileBase does not exist" "Yellow"
        exit 0
    }

    $UsersToFix += $UserName
}
else {
    # Auto-detect
    $DupedFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "\.$([regex]::Escape($DomainSuffix))$" }

    foreach ($Folder in $DupedFolders) {
        $BaseName = $Folder.Name -replace "\.$([regex]::Escape($DomainSuffix))$", ''
        if (Test-Path "C:\Users\$BaseName") {
            $UsersToFix += $BaseName
            Write-Log "  Found duplicate: $BaseName (both C:\Users\$BaseName and $($Folder.FullName) exist)" "Yellow"
        }
    }
}

if ($UsersToFix.Count -eq 0) {
    Write-Log "No duplicate profiles found on this machine" "Green"
    exit 0
}

Write-Log "Found $($UsersToFix.Count) user(s) to fix: $($UsersToFix -join ', ')" "Cyan"

# ============================================================
# 3. Process each user
# ============================================================
$SuccessCount = 0
$ErrorCount   = 0
$FixedUsers   = @()

foreach ($User in $UsersToFix) {
    Write-Host "`n$("=" * 50)" -ForegroundColor DarkCyan
    Write-Log "Starting fix for: $User" "Cyan"

    $UserProfileBase  = "C:\Users\$User"
    $UserProfileDuped = "C:\Users\$User.$DomainSuffix"

    try {
        # ---- Resolve new SID ----
        Write-Log "  Resolving SID for $User"
        $CurrentSid = $null
        $DomainFormats = @("$DomainSuffix\$User", "$env:USERDOMAIN\$User", "$User")
        foreach ($Format in $DomainFormats) {
            try {
                $NtAccount = New-Object System.Security.Principal.NTAccount($Format)
                $CurrentSid = $NtAccount.Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
                Write-Log "  Resolved: $Format -> $CurrentSid" "Green"
                break
            }
            catch { continue }
        }

        if (-not $CurrentSid) {
            Write-Log "  ERROR: Could not resolve SID for $User" "Red"
            $ErrorCount++
            continue
        }

        # ---- Find old SID in ProfileList ----
        $OldSidKey = Get-ChildItem $ProfileListReg | Where-Object {
            (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath -eq $UserProfileBase
        } | Select-Object -First 1

        if (-not $OldSidKey) {
            Write-Log "  No ProfileList entry points to $UserProfileBase - nothing to remap" "Yellow"
            $ErrorCount++
            continue
        }

        $OldSid = $OldSidKey.PSChildName
        Write-Log "  Old SID: $OldSid -> $UserProfileBase"

        # Verify new SID points to .AD
        $NewSidKeyPath = "$ProfileListReg\$CurrentSid"
        $NewSidProfile = $null
        if (Test-Path $NewSidKeyPath) {
            $NewSidProfile = (Get-ItemProperty $NewSidKeyPath -ErrorAction SilentlyContinue).ProfileImagePath
        }

        if ($OldSid -eq $CurrentSid) {
            Write-Log "  Old and new SID are identical - nothing to do" "Green"
            continue
        }

        if ($NewSidProfile -ne $UserProfileDuped) {
            Write-Log "  New SID does not point to $UserProfileDuped (points to: $NewSidProfile) - unexpected state" "Yellow"
            $ErrorCount++
            continue
        }

        Write-Log "  New SID: $CurrentSid -> $NewSidProfile"
        Write-Log "  DUPLICATE CONFIRMED - proceeding with fix" "Yellow"

        # ---- Step 1: Backup ----
        Write-Log "  Step 1/5: Backing up registry key for $OldSid"
        if (-not (Test-Path $BackupDir)) {
            New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        }
        $Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
        $BackupFile = Join-Path $BackupDir "$env:COMPUTERNAME-$User-$Timestamp.reg"
        & reg.exe export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$OldSid" $BackupFile /y 2>&1 | Out-Null
        Write-Log "  Step 1/5: Backup saved: $BackupFile" "Green"

        # ---- Step 2: Delete new SID key ----
        Write-Log "  Step 2/5: Removing new SID key ($CurrentSid)"
        if (Test-Path $NewSidKeyPath) {
            Remove-Item $NewSidKeyPath -Recurse -Force
            Write-Log "  Step 2/5: Removed $CurrentSid (pointed to $UserProfileDuped)" "Green"
        }

        # ---- Step 3: Copy old SID to new SID, delete old ----
        Write-Log "  Step 3/5: Remapping $OldSid -> $CurrentSid"
        Copy-Item $OldSidKey.PSPath "$ProfileListReg\$CurrentSid" -Recurse
        Remove-Item $OldSidKey.PSPath -Recurse -Force

        $VerifyPath = (Get-ItemProperty "$ProfileListReg\$CurrentSid" -ErrorAction SilentlyContinue).ProfileImagePath
        Write-Log "  Step 3/5: Verification: $CurrentSid now points to '$VerifyPath'" "Green"

        # ---- Step 4: Remove .AD folder ----
        Write-Log "  Step 4/5: Removing duplicate folder $UserProfileDuped"
        $EscapedPath = $UserProfileDuped -replace '\\', '\\\\'
        $DupedProfile = Get-CimInstance Win32_UserProfile -Filter "LocalPath='$EscapedPath'" -ErrorAction SilentlyContinue
        if ($DupedProfile) {
            Remove-CimInstance -InputObject $DupedProfile -ErrorAction SilentlyContinue
            Write-Log "  Step 4/5: Removed via Win32_UserProfile" "Green"
        }
        elseif (Test-Path $UserProfileDuped) {
            Remove-Item $UserProfileDuped -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "  Step 4/5: Removed folder directly" "Green"
        }
        else {
            Write-Log "  Step 4/5: Duplicate folder already gone" "Gray"
        }

        # ---- Step 5: Fix NTFS ACLs ----
        Write-Log "  Step 5/5: Updating NTFS permissions on $UserProfileBase"

        $TakeownResult = & takeown.exe /F $UserProfileBase /R /A /D Y 2>&1
        $TakeownLast = ($TakeownResult | Select-Object -Last 1) -as [string]
        Write-Log "  Step 5/5: takeown: $TakeownLast"

        $IcaclsGrant = & icacls.exe $UserProfileBase /grant "*${CurrentSid}:(OI)(CI)F" /T /C /Q 2>&1
        $IcaclsLast = ($IcaclsGrant | Select-Object -Last 1) -as [string]
        Write-Log "  Step 5/5: icacls grant: $IcaclsLast"

        $IcaclsOwner = & icacls.exe $UserProfileBase /setowner "*$CurrentSid" /T /C /Q 2>&1
        $IcaclsOwnerLast = ($IcaclsOwner | Select-Object -Last 1) -as [string]
        Write-Log "  Step 5/5: icacls setowner: $IcaclsOwnerLast"

        $IcaclsRemove = & icacls.exe $UserProfileBase /remove "*$OldSid" /T /C /Q 2>&1
        $IcaclsRemoveLast = ($IcaclsRemove | Select-Object -Last 1) -as [string]
        Write-Log "  Step 5/5: icacls remove old SID: $IcaclsRemoveLast" "Green"

        Write-Log "  FIX COMPLETED for $User" "Green"
        $SuccessCount++
        $FixedUsers += $User
    }
    catch {
        Write-Log "  ERROR fixing ${User}: $($_.Exception.Message)" "Red"
        $ErrorCount++
    }
}

# ============================================================
# 4. Summary
# ============================================================
Write-Host "`n$("=" * 50)" -ForegroundColor Cyan
Write-Log "Done: $SuccessCount fixed, $ErrorCount errors" "Cyan"

if ($SuccessCount -gt 0) {
    Write-Log "Log saved to: $LogFile" "Gray"

    # ---- Notify user(s) to log off ----
    Add-Type -AssemblyName System.Windows.Forms

    $FixedList = $FixedUsers -join ", "
    $Message = "Profile repair completed for: $FixedList`n`n" +
               "Please save your work and log off now.`n" +
               "Your profile will be fully restored after logging back in."

    [System.Windows.Forms.MessageBox]::Show(
        $Message,
        "Profile Repair Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null

    Write-Log "User notification displayed"
}

if ($ErrorCount -gt 0) { exit 1 }
exit 0
