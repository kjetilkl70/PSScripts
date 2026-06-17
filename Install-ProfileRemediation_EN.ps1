<#
.SYNOPSIS
    Intune Remediation - Fix / Deployment
    Installs profile remediation infrastructure on VDI machines.

.DESCRIPTION
    Runs in SYSTEM context via Intune on all VDI machines in scope.
    Writes two PowerShell scripts to C:\ProgramData\ProfileRemediation\
    and registers two scheduled tasks under \ProfileRemediation\ in
    Task Scheduler that run at EVERY user logon:

    Task 1: "ProfileRemediation-Overlay" (user session, immediate)
        - Quick check: does this user have a .<DomainSuffix> profile?
        - No -> exits silently (sub-second, invisible)
        - Yes -> writes request file with user identity (SID, paths)
        - Shows fullscreen WPF overlay "Repairing user-profile..."
        - Polls for signal file from Engine (max 5 min timeout)
        - On signal: shows 10s countdown -> forced logoff

    Task 2: "ProfileRemediation-Engine" (SYSTEM, 5s delay)
        - Reads request file written by Overlay (no user guessing)
        - Validates duplicate pattern in ProfileList registry
        - Backup -> ProfileList remap -> delete .AD profile -> update ACLs -> DONE signal
        - Per-user completion marker prevents repeated execution

    Idempotent: Safe to run multiple times - files and tasks are overwritten.
    Versioned: Detect script triggers reinstallation on version bump.

.NOTES
    Author:  Kjetil Klonteig
    Company:      Sopra Steria
    Version:    4.3.0
    Changelog:
        4.3.0 - Added Step 5 to Engine: updates NTFS ownership and
                 permissions on the original profile folder after registry
                 remap. Ensures new SID has Full Control and ownership,
                 removes old SID from ACLs. Fixes gpsvc access denied
                 errors on machines without sIDHistory resolution.
        4.2.8 - All text, comments, log messages, and instructions
                 translated to English.
        4.2.7 - All Norwegian characters in Install script replaced with ASCII.
                 Added version check so Install skips if
                 already installed. Overlay texts moved to
                 configuration section for easy customization.
        4.2.6 - VBScript launcher also for engine task. Both tasks
                 now run via wscript.exe to eliminate all
                 console window flash at logon.
        4.2.5 - VBScript launcher for overlay task so that PowerShell
                 starts completely hidden (no console window flash at logon).
                 Scheduled task now calls wscript.exe instead of
                 powershell.exe directly.
        4.2.4 - Added Ctrl+Shift+F12 as emergency exit in overlay for
                 troubleshooting (closes overlay without logoff).
        4.2.3 - Fix: Escaped ${CurrentSid} in Set-Content to avoid
                 PowerShell interpreting colon as drive qualifier.
        4.2.1 - Fix: Added missing xmlns:x namespace to WPF XAML.
                 Replaced all non-ASCII characters in embedded scripts to
                 avoid encoding corruption (UTF-8 without BOM is read
                 as Windows-1252 in PowerShell 5.1).
        4.2.0 - Fix: Set explicit ACL (BUILTIN\Users: Modify) on
                 C:\ProgramData\ProfileRemediation\ so that Overlay
                 (user session) can write request, signal, and log files.
                 Added Start-Transcript as fallback logging in both
                 logon scripts (user %TEMP% / ProgramData).
        4.1.0 - Overlay writes request file with user identity - Engine
                 reads it instead of guessing user via WMI.
                 Scheduled tasks moved to \ProfileRemediation\ in
                 Task Scheduler. Comprehensive logging in both logon scripts.
        4.0.0 - New architecture. Deployment to all VDI machines via Intune.
                 Per-user detection and repair at logon.

    Prerequisites:
        - Intune: "Run this script using the logged-on credentials: No"
        - Intune: "Run script in 64-bit PowerShell: Yes"
        - $DomainSuffix below must match the NETBIOS name of
          the new domain (default: "AD")
#>

$ErrorActionPreference = 'Stop'
$ScriptVersion = "4.3.0"

# ============================================================
# Configuration
# ============================================================
$DomainSuffix    = "AD"   # NETBIOS name for new domain - change per environment
$BaseDir         = "C:\ProgramData\ProfileRemediation"
$BackupDir       = Join-Path $BaseDir "Backup"
$CompletedDir    = Join-Path $BaseDir "completed"
$LogDir          = Join-Path $BaseDir "logs"
$VersionFile     = Join-Path $BaseDir "version.txt"
$OverlayScript   = Join-Path $BaseDir "Show-RemediationOverlay.ps1"
$OverlayLauncher = Join-Path $BaseDir "Launch-Overlay.vbs"
$EngineScript    = Join-Path $BaseDir "Invoke-ProfileRemediation.ps1"
$EngineLauncher  = Join-Path $BaseDir "Launch-Engine.vbs"
$TaskPath        = "\ProfileRemediation\"
$TaskNameOverlay = "ProfileRemediation-Overlay"
$TaskNameEngine  = "ProfileRemediation-Engine"

# ============================================================
# Overlay texts (change these to customize user messages)
# ============================================================
$TextRepairing  = "Repairing user-profile, please wait"
$TextLogoff     = "Logging off for completing repairs, please log in again after logoff"
$TextCountdown  = "Logging off in {0} seconds..."
$TextTimeout    = "Repair timed out - please contact IT support."

# ============================================================
# Version check - skip if already installed
# ============================================================
if (Test-Path $VersionFile) {
    $InstalledVersion = (Get-Content $VersionFile -ErrorAction SilentlyContinue).Trim()
    if ($InstalledVersion -eq $ScriptVersion) {
        Write-Output "OK: ProfileRemediation v$ScriptVersion already installed"
        exit 0
    }
}

# ============================================================
# Event Log
# ============================================================
$EventSource  = "ProfileRemediation"
$EventLogName = "Application"
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try { New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction SilentlyContinue } catch { }
}

function Write-InstallLog {
    param([string]$Message, [string]$Level = 'Information')
    Write-Output $Message
    try {
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId 1000 `
            -EntryType $Level -Message "[Install v$ScriptVersion] $Message" -ErrorAction SilentlyContinue
    } catch { }
}

# ============================================================
# 1. Create directory structure
# ============================================================
try {
    foreach ($Dir in @($BaseDir, $BackupDir, $CompletedDir, $LogDir)) {
        if (-not (Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }
    Write-InstallLog "Directory structure created"

    # Set ACL: grant Users modify access so Overlay (user session)
    # can write request files, signal files, and logs.
    $Acl = Get-Acl $BaseDir
    $UsersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Users",
        "Modify",
        "ContainerInherit, ObjectInherit",
        "None",
        "Allow"
    )

    # Check if rule already exists to avoid duplicates
    $ExistingRule = $Acl.Access | Where-Object {
        $_.IdentityReference -eq "BUILTIN\Users" -and
        $_.FileSystemRights -match "Modify"
    }
    if (-not $ExistingRule) {
        $Acl.AddAccessRule($UsersRule)
        Set-Acl -Path $BaseDir -AclObject $Acl
        Write-InstallLog "ACL set: BUILTIN\Users has Modify access to $BaseDir (incl. subfolders)"
    }
    else {
        Write-InstallLog "ACL already correct: BUILTIN\Users has Modify access"
    }

    # ============================================================
    # 2. Remove old tasks from root (upgrade from v4.0.0)
    # ============================================================
    Unregister-ScheduledTask -TaskName $TaskNameOverlay -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskNameEngine  -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue

    # ============================================================
    # 3. Write overlay script (user session at logon)
    # ============================================================
    Write-InstallLog "Writing logon scripts to disk"

    $OverlayTemplate = @'
# ============================================================
# Show-RemediationOverlay.ps1  v4.2.6
# Runs in user session via scheduled task at EVERY logon.
# Exits silently if user has no duplicate.
# Writes request file and shows overlay if duplicate found.
# ============================================================

$DomainSuffix   = "%%SUFFIX%%"
$BaseDir        = "C:\ProgramData\ProfileRemediation"
$CompletedDir   = Join-Path $BaseDir "completed"
$LogDir         = Join-Path $BaseDir "logs"
$MaxWaitSeconds = 300

$UserName    = $env:USERNAME
$RequestFile = Join-Path $BaseDir "request-$UserName.json"
$SignalFile  = Join-Path $BaseDir "signal-$UserName.flag"
$UserMarker  = Join-Path $CompletedDir "$UserName.done"
$LogFile     = Join-Path $LogDir "overlay-$UserName.log"

# Transcript as fallback log - always writes to user TEMP
$TranscriptFile = Join-Path $env:TEMP "ProfileRemediation-Overlay.log"
try { Start-Transcript -Path $TranscriptFile -Append -Force | Out-Null } catch { }

function Write-OverlayLog {
    param([string]$Message)
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $Line = "$Timestamp [Overlay] $Message"
    Add-Content -Path $LogFile -Value $Line -ErrorAction SilentlyContinue
    try {
        Write-EventLog -LogName Application -Source ProfileRemediation -EventId 2000 `
            -EntryType Information -Message "[Overlay] $UserName : $Message" -ErrorAction SilentlyContinue
    } catch { }
}

# ---- Start ----
Write-OverlayLog "Started for user $UserName on $env:COMPUTERNAME"

# ---- Quick check: already fixed? ----
if (Test-Path $UserMarker) {
    Write-OverlayLog "Completion marker found ($UserMarker) - exiting silently"
    exit 0
}

# ---- Quick check: does this user have duplicate pattern? ----
$ProfileBase  = "C:\Users\$UserName"
$ProfileDuped = "C:\Users\$UserName.$DomainSuffix"

Write-OverlayLog "Checking duplicate: ProfileBase=$ProfileBase, ProfileDuped=$ProfileDuped"

if (-not (Test-Path $ProfileDuped)) {
    Write-OverlayLog "No duplicate folder found ($ProfileDuped does not exist) - exiting silently"
    exit 0
}

if (-not (Test-Path $ProfileBase)) {
    Write-OverlayLog "Original folder does not exist ($ProfileBase) - exiting silently"
    exit 0
}

Write-OverlayLog "DUPLICATE DETECTED: Both $ProfileBase and $ProfileDuped exist"

# ---- Collect user identity ----
try {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentSid  = $CurrentUser.User.Value
    $FullName    = $CurrentUser.Name
    Write-OverlayLog "User identity: Name=$FullName, SID=$CurrentSid"
}
catch {
    Write-OverlayLog "ERROR: Could not retrieve user identity: $($_.Exception.Message)"
    exit 1
}

# ---- Write request file for Engine ----
$RequestData = @{
    SamAccount    = $UserName
    CurrentSid    = $CurrentSid
    FullName      = $FullName
    ProfileBase   = $ProfileBase
    ProfileDuped  = $ProfileDuped
    ComputerName  = $env:COMPUTERNAME
    RequestTime   = (Get-Date -Format 'o')
} | ConvertTo-Json -Compress

# Remove any old signal and request files
Remove-Item $SignalFile  -Force -ErrorAction SilentlyContinue
Remove-Item $RequestFile -Force -ErrorAction SilentlyContinue

Set-Content -Path $RequestFile -Value $RequestData -Encoding UTF8 -Force
Write-OverlayLog "Request file written: $RequestFile"

# ---- Show fullscreen WPF overlay ----
Write-OverlayLog "Starting WPF overlay"

try {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase

    Write-OverlayLog "WPF assemblies loaded"

    [xml]$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        WindowStyle="None" AllowsTransparency="True" Background="#E0101010"
        Topmost="True" WindowState="Maximized" ShowInTaskbar="False"
        ResizeMode="NoResize">
    <Window.Resources>
        <Style x:Key="Dot" TargetType="Ellipse">
            <Setter Property="Width" Value="12"/>
            <Setter Property="Height" Value="12"/>
            <Setter Property="Fill" Value="#44FFFFFF"/>
            <Setter Property="Margin" Value="5,0"/>
        </Style>
    </Window.Resources>
    <Grid>
        <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center" MaxWidth="900">
            <TextBlock Name="StatusText"
                       Text="%%TEXT_REPAIRING%%"
                       Foreground="White" FontSize="32" FontWeight="SemiBold"
                       HorizontalAlignment="Center" TextWrapping="Wrap"
                       TextAlignment="Center"/>
            <StackPanel Name="SpinnerPanel" Orientation="Horizontal"
                        HorizontalAlignment="Center" Margin="0,28,0,0">
                <Ellipse Name="Dot1" Style="{StaticResource Dot}"/>
                <Ellipse Name="Dot2" Style="{StaticResource Dot}"/>
                <Ellipse Name="Dot3" Style="{StaticResource Dot}"/>
            </StackPanel>
            <TextBlock Name="CountdownText"
                       Foreground="#AAAAAA" FontSize="20"
                       HorizontalAlignment="Center" Margin="0,20,0,0"
                       Visibility="Collapsed"/>
        </StackPanel>
    </Grid>
</Window>
"@

    $Reader = New-Object System.Xml.XmlNodeReader $Xaml
    $Window = [System.Windows.Markup.XamlReader]::Load($Reader)

    $StatusText    = $Window.FindName("StatusText")
    $SpinnerPanel  = $Window.FindName("SpinnerPanel")
    $CountdownText = $Window.FindName("CountdownText")
    $Dot1          = $Window.FindName("Dot1")
    $Dot2          = $Window.FindName("Dot2")
    $Dot3          = $Window.FindName("Dot3")

    Write-OverlayLog "WPF window created"

    # Block Alt+F4
    $Window.Add_Closing({ param($s, $e)
        if (-not $script:AllowClose) { $e.Cancel = $true }
    })

    # Emergency exit: Ctrl+Shift+F12 closes overlay without logoff (for troubleshooting)
    $Window.Add_PreviewKeyDown({ param($s, $e)
        if ($e.Key -eq 'F12' -and
            [System.Windows.Input.Keyboard]::Modifiers -eq ([System.Windows.Input.ModifierKeys]::Control -bor [System.Windows.Input.ModifierKeys]::Shift)) {
            Write-OverlayLog "EMERGENCY EXIT: Ctrl+Shift+F12 pressed - closing overlay without logoff"
            $script:AllowClose = $true
            $Window.Close()
        }
    })

    # State variables
    $script:AllowClose  = $false
    $script:State       = 'WAITING'
    $script:Countdown   = 10
    $script:WaitTicks   = 0
    $script:DotIndex    = 0

    $HighBrush = [System.Windows.Media.SolidColorBrush]::new(
        [System.Windows.Media.Color]::FromArgb(255, 255, 255, 255))
    $LowBrush  = [System.Windows.Media.SolidColorBrush]::new(
        [System.Windows.Media.Color]::FromArgb(68, 255, 255, 255))
    $Dots = @($Dot1, $Dot2, $Dot3)

    $Timer = New-Object System.Windows.Threading.DispatcherTimer
    $Timer.Interval = [TimeSpan]::FromMilliseconds(800)
    $Timer.Add_Tick({
        switch ($script:State) {

            'WAITING' {
                # Animate spinner
                foreach ($i in 0..2) {
                    $Dots[$i].Fill = if ($i -eq $script:DotIndex) { $HighBrush } else { $LowBrush }
                }
                $script:DotIndex = ($script:DotIndex + 1) % 3

                # Check signal file from Engine
                if (Test-Path $SignalFile) {
                    $Content = (Get-Content $SignalFile -Raw -ErrorAction SilentlyContinue).Trim()
                    Write-OverlayLog "Received signal from Engine: $Content"

                    if ($Content -match '^SKIP') {
                        Write-OverlayLog "Engine reported SKIP - closing overlay silently"
                        $Timer.Stop()
                        $script:AllowClose = $true
                        $Window.Close()
                        return
                    }

                    # DONE or ERROR - show countdown and log off
                    Write-OverlayLog "Switching to countdown (10 seconds to logoff)"
                    $script:State = 'COUNTDOWN'
                    $StatusText.Text = "%%TEXT_LOGOFF%%"
                    $SpinnerPanel.Visibility  = 'Collapsed'
                    $CountdownText.Visibility = 'Visible'
                    $CountdownText.Text = ("%%TEXT_COUNTDOWN%%" -f $script:Countdown)
                    $Timer.Interval = [TimeSpan]::FromSeconds(1)
                    return
                }

                # Timeout check
                $script:WaitTicks++
                $ElapsedSeconds = [math]::Round($script:WaitTicks * 0.8, 0)
                if ($ElapsedSeconds -ge $MaxWaitSeconds) {
                    Write-OverlayLog "TIMEOUT after $MaxWaitSeconds seconds - closing overlay"
                    $Timer.Stop()
                    $StatusText.Text = "%%TEXT_TIMEOUT%%"
                    $SpinnerPanel.Visibility = 'Collapsed'
                    Start-Sleep -Seconds 8
                    $script:AllowClose = $true
                    $Window.Close()
                }
            }

            'COUNTDOWN' {
                $script:Countdown--
                Write-OverlayLog "Countdown: $($script:Countdown) seconds"
                if ($script:Countdown -le 0) {
                    Write-OverlayLog "Countdown complete - running shutdown /l /f"
                    $Timer.Stop()
                    $script:AllowClose = $true
                    $Window.Close()
                    & shutdown.exe /l /f
                }
                else {
                    $CountdownText.Text = ("%%TEXT_COUNTDOWN%%" -f $script:Countdown)
                }
            }
        }
    })

    Write-OverlayLog "Showing overlay - waiting for signal from Engine"
    $Timer.Start()
    $Window.ShowDialog() | Out-Null
    Write-OverlayLog "Overlay closed"
}
catch {
    Write-OverlayLog "ERROR in overlay: $($_.Exception.Message)"
    # Log off if Engine has signaled DONE
    if (Test-Path $SignalFile) {
        $Content = Get-Content $SignalFile -Raw -ErrorAction SilentlyContinue
        if ($Content -match '^DONE') {
            Write-OverlayLog "Engine has signaled DONE - running fallback logoff"
            Start-Sleep -Seconds 3
            & shutdown.exe /l /f
        }
    }
}
'@

    $OverlayFinal = $OverlayTemplate.Replace('%%SUFFIX%%', $DomainSuffix).
        Replace('%%TEXT_REPAIRING%%', $TextRepairing).
        Replace('%%TEXT_LOGOFF%%', $TextLogoff).
        Replace('%%TEXT_COUNTDOWN%%', $TextCountdown).
        Replace('%%TEXT_TIMEOUT%%', $TextTimeout)
    Set-Content -Path $OverlayScript -Value $OverlayFinal -Encoding UTF8 -Force
    Write-InstallLog "Written: $OverlayScript"

    # VBS launcher: starts PowerShell completely hidden (no console window flash)
    $VbsContent = "CreateObject(""WScript.Shell"").Run ""powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File """"$OverlayScript"""""", 0, False"
    Set-Content -Path $OverlayLauncher -Value $VbsContent -Encoding ASCII -Force
    Write-InstallLog "Written: $OverlayLauncher"

    # ============================================================
    # 4. Write engine script (SYSTEM at logon, 5s delay)
    # ============================================================

    $EngineTemplate = @'
# ============================================================
# Invoke-ProfileRemediation.ps1  v4.2.6
# Runs as SYSTEM via scheduled task at EVERY logon (5s delay).
# Reads request file from Overlay to identify user.
# Exits silently if no request. Fixes if duplicate confirmed.
# ============================================================

$ErrorActionPreference = 'Stop'

$DomainSuffix    = "%%SUFFIX%%"
$BaseDir         = "C:\ProgramData\ProfileRemediation"
$BackupDir       = Join-Path $BaseDir "Backup"
$CompletedDir    = Join-Path $BaseDir "completed"
$LogDir          = Join-Path $BaseDir "logs"
$HistoryFile     = Join-Path $BaseDir "remediation-history.csv"
$ProfileListReg  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

# Transcript as fallback log - SYSTEM writes to ProgramData
$TranscriptFile = Join-Path $BaseDir "logs\engine-transcript.log"
try { Start-Transcript -Path $TranscriptFile -Append -Force | Out-Null } catch { }

$EventSource  = "ProfileRemediation"
$EventLogName = "Application"
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try { New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction SilentlyContinue } catch { }
}

# Common log function - writes to Event Log + file
$script:LogUser = "unknown"
function Write-EngineLog {
    param([string]$Message, [string]$Level = 'Information')
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $Line = "$Timestamp [Engine] $Message"
    $EngineLogFile = Join-Path $LogDir "engine-$($script:LogUser).log"
    Add-Content -Path $EngineLogFile -Value $Line -ErrorAction SilentlyContinue
    try {
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId 2001 `
            -EntryType $Level -Message "[Engine] $($script:LogUser) : $Message" -ErrorAction SilentlyContinue
    } catch { }
}

Write-EngineLog "Engine started on $env:COMPUTERNAME"

# ============================================================
# 1. Wait for and read request file from Overlay
# ============================================================
Write-EngineLog "Searching for request files in $BaseDir"

$RequestFile = $null
$Request     = $null

for ($Retry = 0; $Retry -lt 10; $Retry++) {
    $RequestFiles = Get-ChildItem -Path $BaseDir -Filter "request-*.json" -ErrorAction SilentlyContinue
    if ($RequestFiles) {
        $RequestFile = $RequestFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-EngineLog "Found request file: $($RequestFile.Name) (attempt $($Retry + 1))"
        break
    }
    Write-EngineLog "No request file found (attempt $($Retry + 1)/10) - waiting 2 seconds"
    Start-Sleep -Seconds 2
}

if (-not $RequestFile) {
    Write-EngineLog "No request file after 10 attempts (20s) - no user needs fix, exiting"
    exit 0
}

# Parse request
try {
    $Request = Get-Content $RequestFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
    $script:LogUser = $Request.SamAccount
    Write-EngineLog "Request parsed: SamAccount=$($Request.SamAccount), SID=$($Request.CurrentSid), ProfileBase=$($Request.ProfileBase), ProfileDuped=$($Request.ProfileDuped)"
}
catch {
    Write-EngineLog "ERROR: Could not parse request file $($RequestFile.Name): $($_.Exception.Message)" -Level Error
    exit 1
}

$SamAccount      = $Request.SamAccount
$CurrentSid      = $Request.CurrentSid
$UserProfileBase = $Request.ProfileBase
$UserProfileDuped= $Request.ProfileDuped
$SignalFile      = Join-Path $BaseDir "signal-$SamAccount.flag"
$UserMarker      = Join-Path $CompletedDir "$SamAccount.done"

# ============================================================
# 2. Already fixed for this user?
# ============================================================
if (Test-Path $UserMarker) {
    Write-EngineLog "Completion marker found ($UserMarker) - signaling SKIP"
    Set-Content -Path $SignalFile -Value "SKIP:already-completed" -Force
    Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
    Write-EngineLog "Request file removed, exiting"
    exit 0
}

try {
    # ============================================================
    # 3. Validate duplicate pattern in filesystem
    # ============================================================
    Write-EngineLog "Validating filesystem: ProfileBase=$UserProfileBase, ProfileDuped=$UserProfileDuped"

    if (-not (Test-Path $UserProfileDuped)) {
        Write-EngineLog "Duplicate folder does not exist ($UserProfileDuped) - signaling SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:no-duplicate" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    if (-not (Test-Path $UserProfileBase)) {
        Write-EngineLog "Original folder does not exist ($UserProfileBase) - signaling SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:no-original" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    Write-EngineLog "Both folders confirmed on disk"

    # ============================================================
    # 4. Validate ProfileList in registry
    # ============================================================
    Write-EngineLog "Reading ProfileList from $ProfileListReg"

    $AllProfiles = Get-ChildItem $ProfileListReg -ErrorAction Stop | ForEach-Object {
        $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Sid              = $_.PSChildName
            ProfileImagePath = $Props.ProfileImagePath
            PSPath           = $_.PSPath
        }
    }

    Write-EngineLog "Found $($AllProfiles.Count) ProfileList entries total"

    # Find old SID (owner of original folder)
    $OldSidEntry = $AllProfiles | Where-Object { $_.ProfileImagePath -eq $UserProfileBase }
    if (-not $OldSidEntry) {
        Write-EngineLog "No ProfileList entry points to $UserProfileBase - signalerer SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:no-old-sid" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    $OldSid = $OldSidEntry.Sid
    Write-EngineLog "Old SID found: $OldSid -> $UserProfileBase"

    # Verify that new SID points to .AD profile
    $NewSidEntry = $AllProfiles | Where-Object { $_.Sid -eq $CurrentSid }
    if (-not $NewSidEntry) {
        Write-EngineLog "Ny SID ($CurrentSid) not found in ProfileList - signaling SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:new-sid-missing" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    Write-EngineLog "New SID found: $CurrentSid -> $($NewSidEntry.ProfileImagePath)"

    if ($OldSid -eq $CurrentSid) {
        Write-EngineLog "Old and new SID are identical ($OldSid) - nothing to do"
        Set-Content -Path $SignalFile -Value "SKIP:sid-identical" -Force
        Set-Content -Path $UserMarker -Value "NOACTION:SID-identical:$(Get-Date -Format 'o')" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    if ($NewSidEntry.ProfileImagePath -ne $UserProfileDuped) {
        Write-EngineLog "New SID points to '$($NewSidEntry.ProfileImagePath)', ikke '$UserProfileDuped' - unexpected, signaling SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:unexpected-path" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    # ============================================================
    # DUPLIKAT BEKREFTET - starter reparasjon
    # ============================================================
    Write-EngineLog "========================================="
    Write-EngineLog "DUPLICATE CONFIRMED - STARTING REMEDIATION"
    Write-EngineLog "  User:     $SamAccount"
    Write-EngineLog "  Old SID: $OldSid -> $UserProfileBase"
    Write-EngineLog "  New SID:     $CurrentSid -> $UserProfileDuped"
    Write-EngineLog "  Machine:     $env:COMPUTERNAME"
    Write-EngineLog "========================================="

    # ---- Step 1: Backup old ProfileList key ----
    Write-EngineLog "Step 1/5: Exporting registry backup"
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
    $Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $BackupFile = Join-Path $BackupDir "$env:COMPUTERNAME-$SamAccount-$Timestamp.reg"
    $RegExport = & reg.exe export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$OldSid" $BackupFile /y 2>&1
    Write-EngineLog "Step 1/5: Backup saved: $BackupFile (reg.exe output: $RegExport)"

    # ---- Step 2: Delete new SID key (points to .AD) ----
    Write-EngineLog "Step 2/5: Removing new SID key ($CurrentSid)"
    $NewSidKeyPath = "$ProfileListReg\$CurrentSid"
    if (Test-Path $NewSidKeyPath) {
        Remove-Item $NewSidKeyPath -Recurse -Force
        Write-EngineLog "Step 2/5: Removed $NewSidKeyPath (pointed to $UserProfileDuped)"
    }
    else {
        Write-EngineLog "Steg 2/4: $NewSidKeyPath did not exist - continuing"
    }

    # ---- Step 3: Copy old SID to new SID, delete old ----
    Write-EngineLog "Step 3/5: Copying $OldSid -> $CurrentSid"
    Copy-Item $OldSidEntry.PSPath "$ProfileListReg\$CurrentSid" -Recurse
    Write-EngineLog "Step 3/5: Copy complete, deleting old key $OldSid"
    Remove-Item $OldSidEntry.PSPath -Recurse -Force
    Write-EngineLog "Step 3/5: ProfileList remapped: $OldSid -> $CurrentSid"

    # Verify remapping
    $VerifyPath = (Get-ItemProperty "$ProfileListReg\$CurrentSid" -ErrorAction SilentlyContinue).ProfileImagePath
    Write-EngineLog "Step 3/5: Verification: $CurrentSid now points to '$VerifyPath'"

    # ---- Step 4: Remove duplicate profile folder ----
    Write-EngineLog "Step 4/5: Removing duplicate profile $UserProfileDuped"
    $EscapedPath  = $UserProfileDuped -replace '\\', '\\\\'
    $DupedProfile = Get-CimInstance Win32_UserProfile -Filter "LocalPath='$EscapedPath'" -ErrorAction SilentlyContinue

    if ($DupedProfile) {
        Write-EngineLog "Step 4/5: Found Win32_UserProfile for $UserProfileDuped - removing via CIM"
        Remove-CimInstance -InputObject $DupedProfile -ErrorAction SilentlyContinue
        Write-EngineLog "Step 4/5: Win32_UserProfile removed"
    }
    elseif (Test-Path $UserProfileDuped) {
        Write-EngineLog "Step 4/5: No Win32_UserProfile found - removing folder directly"
        Remove-Item $UserProfileDuped -Recurse -Force -ErrorAction SilentlyContinue
        Write-EngineLog "Step 4/5: Folder removed"
    }
    else {
        Write-EngineLog "Step 4/5: Duplicate folder already gone"
    }

    # ---- Step 5: Update NTFS ACLs on original profile folder ----
    Write-EngineLog "Step 5/5: Updating NTFS permissions on $UserProfileBase"
    Write-EngineLog "Step 5/5: Taking ownership for $CurrentSid ($SamAccount)"

    # Take ownership of the entire profile tree
    $TakeownResult = & takeown.exe /F $UserProfileBase /R /A /D Y 2>&1
    $TakeownLast = ($TakeownResult | Select-Object -Last 1) -as [string]
    Write-EngineLog "Step 5/5: takeown completed: $TakeownLast"

    # Grant Full Control to the new SID (recursive, applies to this folder, subfolders, and files)
    $IcaclsGrant = & icacls.exe $UserProfileBase /grant "*${CurrentSid}:(OI)(CI)F" /T /C /Q 2>&1
    $IcaclsLast = ($IcaclsGrant | Select-Object -Last 1) -as [string]
    Write-EngineLog "Step 5/5: icacls grant completed: $IcaclsLast"

    # Set the new SID as owner (takeown /A sets Administrators, this sets the actual user)
    $IcaclsOwner = & icacls.exe $UserProfileBase /setowner "*$CurrentSid" /T /C /Q 2>&1
    $IcaclsOwnerLast = ($IcaclsOwner | Select-Object -Last 1) -as [string]
    Write-EngineLog "Step 5/5: icacls setowner completed: $IcaclsOwnerLast"

    # Remove the old SID from ACLs (cleanup, non-critical)
    $IcaclsRemove = & icacls.exe $UserProfileBase /remove "*$OldSid" /T /C /Q 2>&1
    $IcaclsRemoveLast = ($IcaclsRemove | Select-Object -Last 1) -as [string]
    Write-EngineLog "Step 5/5: icacls remove old SID completed: $IcaclsRemoveLast"

    Write-EngineLog "Step 5/5: NTFS permissions updated for $SamAccount on $UserProfileBase"

    # ---- Telemetry and markers ----
    Write-EngineLog "Writing telemetry and markers"

    if (-not (Test-Path $CompletedDir)) {
        New-Item -ItemType Directory -Path $CompletedDir -Force | Out-Null
    }

    $HistoryLine = "$SamAccount,$OldSid,$CurrentSid,$env:COMPUTERNAME,$(Get-Date -Format 'o')"
    Add-Content $HistoryFile -Value $HistoryLine -ErrorAction SilentlyContinue
    Write-EngineLog "History written: $HistoryLine"

    Set-Content -Path $UserMarker -Value "OK:$OldSid->${CurrentSid}:$(Get-Date -Format 'o')" -Force
    Write-EngineLog "Completion marker written: $UserMarker"

    # ---- Signal overlay ----
    Set-Content -Path $SignalFile -Value "DONE:$(Get-Date -Format 'o')" -Force
    Write-EngineLog "Signal DONE written: $SignalFile"

    # ---- Clean up request file ----
    Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
    Write-EngineLog "Request file removed"

    Write-EngineLog "========================================="
    Write-EngineLog "REMEDIATION COMPLETED for $SamAccount"
    Write-EngineLog "  Old SID: $OldSid (removed)"
    Write-EngineLog "  New SID:     $CurrentSid (now points to $UserProfileBase)"
    Write-EngineLog "  Overlay will log off user in ~10 seconds"
    Write-EngineLog "========================================="
    exit 0
}
catch {
    Write-EngineLog "CRITICAL ERROR: $($_.Exception.Message)" -Level Error
    Write-EngineLog "Stack trace: $($_.ScriptStackTrace)" -Level Error
    # Signal overlay so user does not get stuck
    Set-Content -Path $SignalFile -Value "ERROR:$($_.Exception.Message)" -Force
    Write-EngineLog "Signal ERROR written - overlay will log off user"
    exit 1
}
'@

    $EngineFinal = $EngineTemplate.Replace('%%SUFFIX%%', $DomainSuffix)
    Set-Content -Path $EngineScript -Value $EngineFinal -Encoding UTF8 -Force
    Write-InstallLog "Written: $EngineScript"

    # VBS launcher for Engine: starts PowerShell completely hidden
    $EngineVbsContent = "CreateObject(""WScript.Shell"").Run ""powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File """"$EngineScript"""""", 0, False"
    Set-Content -Path $EngineLauncher -Value $EngineVbsContent -Encoding ASCII -Force
    Write-InstallLog "Written: $EngineLauncher"

    # ============================================================
    # 5. Create scheduled tasks under \ProfileRemediation\
    # ============================================================
    Write-InstallLog "Registering scheduled tasks under $TaskPath"

    # Remove existing (idempotent reinstallation)
    Unregister-ScheduledTask -TaskName $TaskNameOverlay -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskNameEngine  -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue

    # --- Task 1: Overlay (user session, interactive, immediate) ---
    $OverlayAction = New-ScheduledTaskAction -Execute "wscript.exe" `
        -Argument "`"$OverlayLauncher`""

    $OverlayTrigger = New-ScheduledTaskTrigger -AtLogOn

    $OverlayPrincipal = New-ScheduledTaskPrincipal `
        -GroupId "S-1-5-32-545" -RunLevel Limited

    $OverlaySettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -MultipleInstances Parallel

    Register-ScheduledTask -TaskName $TaskNameOverlay -TaskPath $TaskPath `
        -Action $OverlayAction -Trigger $OverlayTrigger `
        -Principal $OverlayPrincipal -Settings $OverlaySettings `
        -Description "Shows status message during profile remediation (v$ScriptVersion)" `
        -Force | Out-Null

    Write-InstallLog "Task '$TaskPath$TaskNameOverlay' registered (user session, at logon)"

    # --- Task 2: Engine (SYSTEM, 5 second delay) ---
    $EngineAction = New-ScheduledTaskAction -Execute "wscript.exe" `
        -Argument "`"$EngineLauncher`""

    $EngineTrigger = New-ScheduledTaskTrigger -AtLogOn
    $EngineTrigger.Delay = "PT5S"

    $EnginePrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" -RunLevel Highest

    $EngineSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -MultipleInstances Parallel

    Register-ScheduledTask -TaskName $TaskNameEngine -TaskPath $TaskPath `
        -Action $EngineAction -Trigger $EngineTrigger `
        -Principal $EnginePrincipal -Settings $EngineSettings `
        -Description "Performs profile remediation at logon (v$ScriptVersion)" `
        -Force | Out-Null

    Write-InstallLog "Task '$TaskPath$TaskNameEngine' registered (SYSTEM, 5s delay)"

    # ============================================================
    # 6. Write version marker
    # ============================================================
    Set-Content -Path $VersionFile -Value $ScriptVersion -Encoding UTF8 -Force

    Write-InstallLog "Installation completed v$ScriptVersion on $env:COMPUTERNAME"
    exit 0
}
catch {
    Write-InstallLog "ERROR in installation: $($_.Exception.Message)" -Level Error
    exit 1
}
