<#
.SYNOPSIS
    Intune Remediation - Fix / Deployment
    Installerer profilreparasjons-infrastruktur paa VDI-maskiner.

.DESCRIPTION
    Kjoeres i SYSTEM-kontekst via Intune paa alle VDI-maskiner i scope.
    Skriver to PowerShell-script til C:\ProgramData\ProfileRemediation\
    og registrerer to scheduled tasks under \ProfileRemediation\ i
    Task Scheduler som kjoerer ved HVER brukerlogon:

    Task 1: "ProfileRemediation-Overlay" (brukersesjon, umiddelbart)
        - Hurtigsjekk: har denne brukeren en .<DomainSuffix>-profil?
        - Nei -> avslutter stille (sub-sekund, usynlig)
        - Ja -> skriver request-fil med brukeridentitet (SID, stier)
        - Viser fullskjerm WPF-overlay "Repairing user-profile..."
        - Poller for signalfil fra Engine (maks 5 min timeout)
        - Ved signal: viser nedtelling 10s -> tvungen logoff

    Task 2: "ProfileRemediation-Engine" (SYSTEM, 5s delay)
        - Leser request-fil skrevet av Overlay (ingen brukergjetting)
        - Validerer duplikatmoenster i ProfileList-registeret
        - Backup -> ProfileList-remap -> slett .AD-profil -> DONE-signal
        - Per-bruker completion-markoer forhindrer gjentatt kjoering

    Idempotent: Trygt aa kjoere flere ganger - filer og tasks overskrives.
    Versjonert: Detect-scriptet trigger reinstallasjon ved versjonsoekning.

.NOTES
    Forfatter:  Kjetil Klonteig
    Firma:      Sopra Steria
    Versjon:    4.2.7
    Changelog:
        4.2.7 - Alle norske tegn i Install-scriptet erstattet med ASCII.
                 Lagt til versjonsjekk saa Install hopper over hvis
                 allerede installert. Overlay-tekster flyttet til
                 konfigurasjonsseksjonen for enkel tilpasning.
        4.2.6 - VBScript-launcher ogsaa for engine-tasken. Begge tasks
                 kjorer naa via wscript.exe for aa eliminere all
                 konsollvindu-flash ved logon.
        4.2.5 - VBScript-launcher for overlay-tasken slik at PowerShell
                 startes helt usynlig (ingen konsollvindu-flash ved logon).
                 Scheduled task kaller naa wscript.exe i stedet for
                 powershell.exe direkte.
        4.2.4 - Lagt til Ctrl+Shift+F12 som noedutgang i overlay for
                 feilsoeking (lukker overlay uten logoff).
        4.2.3 - Fix: Escaped ${CurrentSid} i Set-Content for aa unngaa
                 at PowerShell tolker kolon som drive-kvalifiserer.
        4.2.1 - Fix: Lagt til manglende xmlns:x namespace i WPF XAML.
                 Erstattet alle ikke-ASCII-tegn i innebygde script for
                 aa unngaa encoding-korrupsjon (UTF-8 uten BOM leses
                 som Windows-1252 i PowerShell 5.1).
        4.2.0 - Fix: Satt eksplisitt ACL (BUILTIN\Users: Modify) paa
                 C:\ProgramData\ProfileRemediation\ slik at Overlay
                 (brukersesjon) kan skrive request-, signal- og loggfiler.
                 Lagt til Start-Transcript som fallback-logging i begge
                 logon-script (brukerens %TEMP% / ProgramData).
        4.1.0 - Overlay skriver request-fil med brukeridentitet - Engine
                 leser denne i stedet for aa gjette bruker via WMI.
                 Scheduled tasks flyttet til \ProfileRemediation\ i
                 Task Scheduler. Omfattende logging i begge logon-script.
        4.0.0 - Ny arkitektur. Utrulling til alle VDI-maskiner via Intune.
                 Deteksjon og reparasjon per bruker ved logon.

    Forutsetninger:
        - Intune: "Run this script using the logged-on credentials: No"
        - Intune: "Run script in 64-bit PowerShell: Yes"
        - $DomainSuffix nedenfor samsvarer med NETBIOS-navnet til
          det nye domenet (standard: "AD")
#>

$ErrorActionPreference = 'Stop'
$ScriptVersion = "4.2.7"

# ============================================================
# Konfigurasjon
# ============================================================
$DomainSuffix    = "AD"   # NETBIOS-navn for nytt domene - endres per miljoe
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
# Overlay-tekster (endre disse for aa tilpasse brukermelding)
# ============================================================
$TextRepairing  = "Repairing user-profile, please wait"
$TextLogoff     = "Logging off to completing repairs, please log in again after"
$TextCountdown  = "Logging off in {0} seconds..."
$TextTimeout    = "Repair timed out - please contact IT support."

# ============================================================
# Versjonsjekk - hopp over hvis allerede installert
# ============================================================
if (Test-Path $VersionFile) {
    $InstalledVersion = (Get-Content $VersionFile -ErrorAction SilentlyContinue).Trim()
    if ($InstalledVersion -eq $ScriptVersion) {
        Write-Output "OK: ProfileRemediation v$ScriptVersion allerede installert"
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
# 1. Opprett mappestruktur
# ============================================================
try {
    foreach ($Dir in @($BaseDir, $BackupDir, $CompletedDir, $LogDir)) {
        if (-not (Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }
    Write-InstallLog "Mappestruktur opprettet"

    # Sett ACL: gi Users modify-tilgang slik at Overlay (brukersesjon)
    # kan skrive request-filer, signalfiler og logger.
    $Acl = Get-Acl $BaseDir
    $UsersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Users",
        "Modify",
        "ContainerInherit, ObjectInherit",
        "None",
        "Allow"
    )

    # Sjekk om regelen allerede finnes for aa unngaa duplikater
    $ExistingRule = $Acl.Access | Where-Object {
        $_.IdentityReference -eq "BUILTIN\Users" -and
        $_.FileSystemRights -match "Modify"
    }
    if (-not $ExistingRule) {
        $Acl.AddAccessRule($UsersRule)
        Set-Acl -Path $BaseDir -AclObject $Acl
        Write-InstallLog "ACL satt: BUILTIN\Users har Modify-tilgang til $BaseDir (inkl. undermapper)"
    }
    else {
        Write-InstallLog "ACL allerede korrekt: BUILTIN\Users har Modify-tilgang"
    }

    # ============================================================
    # 2. Fjern gamle tasks fra rot (oppgradering fra v4.0.0)
    # ============================================================
    Unregister-ScheduledTask -TaskName $TaskNameOverlay -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskNameEngine  -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue

    # ============================================================
    # 3. Skriv overlay-script (brukersesjon ved logon)
    # ============================================================
    Write-InstallLog "Skriver logon-script til disk"

    $OverlayTemplate = @'
# ============================================================
# Show-RemediationOverlay.ps1  v4.2.6
# Kjoeres i brukersesjon via scheduled task ved HVER logon.
# Avslutter stille hvis bruker ikke har duplikat.
# Skriver request-fil og viser overlay hvis duplikat.
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

# Transcript som fallback-log - skriver alltid til brukerens TEMP
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
Write-OverlayLog "Startet for bruker $UserName paa $env:COMPUTERNAME"

# ---- Hurtigsjekk: allerede fikset? ----
if (Test-Path $UserMarker) {
    Write-OverlayLog "Completion-markoer finnes ($UserMarker) - avslutter stille"
    exit 0
}

# ---- Hurtigsjekk: har denne brukeren duplikatmoenster? ----
$ProfileBase  = "C:\Users\$UserName"
$ProfileDuped = "C:\Users\$UserName.$DomainSuffix"

Write-OverlayLog "Sjekker duplikat: ProfileBase=$ProfileBase, ProfileDuped=$ProfileDuped"

if (-not (Test-Path $ProfileDuped)) {
    Write-OverlayLog "Ingen duplikatmappe funnet ($ProfileDuped finnes ikke) - avslutter stille"
    exit 0
}

if (-not (Test-Path $ProfileBase)) {
    Write-OverlayLog "Originalmappe finnes ikke ($ProfileBase) - avslutter stille"
    exit 0
}

Write-OverlayLog "DUPLIKAT OPPDAGET: Baade $ProfileBase og $ProfileDuped finnes"

# ---- Samle brukeridentitet ----
try {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentSid  = $CurrentUser.User.Value
    $FullName    = $CurrentUser.Name
    Write-OverlayLog "Brukeridentitet: Name=$FullName, SID=$CurrentSid"
}
catch {
    Write-OverlayLog "FEIL: Kunne ikke hente brukeridentitet: $($_.Exception.Message)"
    exit 1
}

# ---- Skriv request-fil for Engine ----
$RequestData = @{
    SamAccount    = $UserName
    CurrentSid    = $CurrentSid
    FullName      = $FullName
    ProfileBase   = $ProfileBase
    ProfileDuped  = $ProfileDuped
    ComputerName  = $env:COMPUTERNAME
    RequestTime   = (Get-Date -Format 'o')
} | ConvertTo-Json -Compress

# Fjern evt. gammel signal- og request-fil
Remove-Item $SignalFile  -Force -ErrorAction SilentlyContinue
Remove-Item $RequestFile -Force -ErrorAction SilentlyContinue

Set-Content -Path $RequestFile -Value $RequestData -Encoding UTF8 -Force
Write-OverlayLog "Request-fil skrevet: $RequestFile"

# ---- Vis fullskjerm WPF-overlay ----
Write-OverlayLog "Starter WPF-overlay"

try {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase

    Write-OverlayLog "WPF-assemblies lastet"

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

    Write-OverlayLog "WPF-vindu opprettet"

    # Blokker Alt+F4
    $Window.Add_Closing({ param($s, $e)
        if (-not $script:AllowClose) { $e.Cancel = $true }
    })

    # Noedutgang: Ctrl+Shift+F12 lukker overlay uten logoff (for feilsoeking)
    $Window.Add_PreviewKeyDown({ param($s, $e)
        if ($e.Key -eq 'F12' -and
            [System.Windows.Input.Keyboard]::Modifiers -eq ([System.Windows.Input.ModifierKeys]::Control -bor [System.Windows.Input.ModifierKeys]::Shift)) {
            Write-OverlayLog "NOEDUTGANG: Ctrl+Shift+F12 trykket - lukker overlay uten logoff"
            $script:AllowClose = $true
            $Window.Close()
        }
    })

    # Tilstandsvariabler
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
                # Animer spinner
                foreach ($i in 0..2) {
                    $Dots[$i].Fill = if ($i -eq $script:DotIndex) { $HighBrush } else { $LowBrush }
                }
                $script:DotIndex = ($script:DotIndex + 1) % 3

                # Sjekk signalfil fra Engine
                if (Test-Path $SignalFile) {
                    $Content = (Get-Content $SignalFile -Raw -ErrorAction SilentlyContinue).Trim()
                    Write-OverlayLog "Mottok signal fra Engine: $Content"

                    if ($Content -match '^SKIP') {
                        Write-OverlayLog "Engine meldte SKIP - lukker overlay stille"
                        $Timer.Stop()
                        $script:AllowClose = $true
                        $Window.Close()
                        return
                    }

                    # DONE eller ERROR - vis nedtelling og logg av
                    Write-OverlayLog "Bytter til nedtelling (10 sekunder til logoff)"
                    $script:State = 'COUNTDOWN'
                    $StatusText.Text = "%%TEXT_LOGOFF%%"
                    $SpinnerPanel.Visibility  = 'Collapsed'
                    $CountdownText.Visibility = 'Visible'
                    $CountdownText.Text = ("%%TEXT_COUNTDOWN%%" -f $script:Countdown)
                    $Timer.Interval = [TimeSpan]::FromSeconds(1)
                    return
                }

                # Timeout-sjekk
                $script:WaitTicks++
                $ElapsedSeconds = [math]::Round($script:WaitTicks * 0.8, 0)
                if ($ElapsedSeconds -ge $MaxWaitSeconds) {
                    Write-OverlayLog "TIMEOUT etter $MaxWaitSeconds sekunder - lukker overlay"
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
                Write-OverlayLog "Nedtelling: $($script:Countdown) sekunder"
                if ($script:Countdown -le 0) {
                    Write-OverlayLog "Nedtelling ferdig - kjorer shutdown /l /f"
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

    Write-OverlayLog "Viser overlay - venter paa signal fra Engine"
    $Timer.Start()
    $Window.ShowDialog() | Out-Null
    Write-OverlayLog "Overlay lukket"
}
catch {
    Write-OverlayLog "FEIL i overlay: $($_.Exception.Message)"
    # Logg av hvis Engine har signalert DONE
    if (Test-Path $SignalFile) {
        $Content = Get-Content $SignalFile -Raw -ErrorAction SilentlyContinue
        if ($Content -match '^DONE') {
            Write-OverlayLog "Engine har signalert DONE - kjorer fallback logoff"
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
    Write-InstallLog "Skrevet: $OverlayScript"

    # VBS-launcher: starter PowerShell helt usynlig (ingen konsollvindu-flash)
    $VbsContent = "CreateObject(""WScript.Shell"").Run ""powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File """"$OverlayScript"""""", 0, False"
    Set-Content -Path $OverlayLauncher -Value $VbsContent -Encoding ASCII -Force
    Write-InstallLog "Skrevet: $OverlayLauncher"

    # ============================================================
    # 4. Skriv engine-script (SYSTEM ved logon, 5s delay)
    # ============================================================

    $EngineTemplate = @'
# ============================================================
# Invoke-ProfileRemediation.ps1  v4.2.6
# Kjoeres som SYSTEM via scheduled task ved HVER logon (5s delay).
# Leser request-fil fra Overlay for aa identifisere brukeren.
# Avslutter stille hvis ingen request. Fikser hvis duplikat bekreftet.
# ============================================================

$ErrorActionPreference = 'Stop'

$DomainSuffix    = "%%SUFFIX%%"
$BaseDir         = "C:\ProgramData\ProfileRemediation"
$BackupDir       = Join-Path $BaseDir "Backup"
$CompletedDir    = Join-Path $BaseDir "completed"
$LogDir          = Join-Path $BaseDir "logs"
$HistoryFile     = Join-Path $BaseDir "remediation-history.csv"
$ProfileListReg  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

# Transcript som fallback-log - SYSTEM skriver til ProgramData
$TranscriptFile = Join-Path $BaseDir "logs\engine-transcript.log"
try { Start-Transcript -Path $TranscriptFile -Append -Force | Out-Null } catch { }

$EventSource  = "ProfileRemediation"
$EventLogName = "Application"
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try { New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction SilentlyContinue } catch { }
}

# Felles loggfunksjon - skriver til Event Log + fil
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

Write-EngineLog "Engine startet paa $env:COMPUTERNAME"

# ============================================================
# 1. Vent paa og les request-fil fra Overlay
# ============================================================
Write-EngineLog "Leter etter request-filer i $BaseDir"

$RequestFile = $null
$Request     = $null

for ($Retry = 0; $Retry -lt 10; $Retry++) {
    $RequestFiles = Get-ChildItem -Path $BaseDir -Filter "request-*.json" -ErrorAction SilentlyContinue
    if ($RequestFiles) {
        $RequestFile = $RequestFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-EngineLog "Fant request-fil: $($RequestFile.Name) (forsoek $($Retry + 1))"
        break
    }
    Write-EngineLog "Ingen request-fil funnet (forsoek $($Retry + 1)/10) - venter 2 sekunder"
    Start-Sleep -Seconds 2
}

if (-not $RequestFile) {
    Write-EngineLog "Ingen request-fil etter 10 forsoek (20s) - ingen bruker trenger fix, avslutter"
    exit 0
}

# Parse request
try {
    $Request = Get-Content $RequestFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
    $script:LogUser = $Request.SamAccount
    Write-EngineLog "Request parset: SamAccount=$($Request.SamAccount), SID=$($Request.CurrentSid), ProfileBase=$($Request.ProfileBase), ProfileDuped=$($Request.ProfileDuped)"
}
catch {
    Write-EngineLog "FEIL: Kunne ikke parse request-fil $($RequestFile.Name): $($_.Exception.Message)" -Level Error
    exit 1
}

$SamAccount      = $Request.SamAccount
$CurrentSid      = $Request.CurrentSid
$UserProfileBase = $Request.ProfileBase
$UserProfileDuped= $Request.ProfileDuped
$SignalFile      = Join-Path $BaseDir "signal-$SamAccount.flag"
$UserMarker      = Join-Path $CompletedDir "$SamAccount.done"

# ============================================================
# 2. Allerede fikset for denne brukeren?
# ============================================================
if (Test-Path $UserMarker) {
    Write-EngineLog "Completion-markoer finnes ($UserMarker) - signalerer SKIP"
    Set-Content -Path $SignalFile -Value "SKIP:allerede-fullfoert" -Force
    Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
    Write-EngineLog "Request-fil fjernet, avslutter"
    exit 0
}

try {
    # ============================================================
    # 3. Valider duplikatmoenster i filsystemet
    # ============================================================
    Write-EngineLog "Validerer filsystem: ProfileBase=$UserProfileBase, ProfileDuped=$UserProfileDuped"

    if (-not (Test-Path $UserProfileDuped)) {
        Write-EngineLog "Duplikatmappe finnes ikke ($UserProfileDuped) - signalerer SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:ingen-duplikat" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    if (-not (Test-Path $UserProfileBase)) {
        Write-EngineLog "Originalmappe finnes ikke ($UserProfileBase) - signalerer SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:ingen-original" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    Write-EngineLog "Begge mapper bekreftet paa disk"

    # ============================================================
    # 4. Valider ProfileList i registry
    # ============================================================
    Write-EngineLog "Leser ProfileList fra $ProfileListReg"

    $AllProfiles = Get-ChildItem $ProfileListReg -ErrorAction Stop | ForEach-Object {
        $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Sid              = $_.PSChildName
            ProfileImagePath = $Props.ProfileImagePath
            PSPath           = $_.PSPath
        }
    }

    Write-EngineLog "Fant $($AllProfiles.Count) ProfileList-oppfoeringer totalt"

    # Finn gammel SID (eier av originalmappen)
    $OldSidEntry = $AllProfiles | Where-Object { $_.ProfileImagePath -eq $UserProfileBase }
    if (-not $OldSidEntry) {
        Write-EngineLog "Ingen ProfileList-oppfoering peker paa $UserProfileBase - signalerer SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:ingen-gammel-sid" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    $OldSid = $OldSidEntry.Sid
    Write-EngineLog "Gammel SID funnet: $OldSid -> $UserProfileBase"

    # Verifiser at ny SID peker paa .AD-profilen
    $NewSidEntry = $AllProfiles | Where-Object { $_.Sid -eq $CurrentSid }
    if (-not $NewSidEntry) {
        Write-EngineLog "Ny SID ($CurrentSid) finnes ikke i ProfileList - signalerer SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:ny-sid-mangler" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    Write-EngineLog "Ny SID funnet: $CurrentSid -> $($NewSidEntry.ProfileImagePath)"

    if ($OldSid -eq $CurrentSid) {
        Write-EngineLog "Gammel og ny SID er like ($OldSid) - ingenting aa gjoere"
        Set-Content -Path $SignalFile -Value "SKIP:sid-identisk" -Force
        Set-Content -Path $UserMarker -Value "NOACTION:SID-identisk:$(Get-Date -Format 'o')" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    if ($NewSidEntry.ProfileImagePath -ne $UserProfileDuped) {
        Write-EngineLog "Ny SID peker paa '$($NewSidEntry.ProfileImagePath)', ikke '$UserProfileDuped' - uventet, signalerer SKIP"
        Set-Content -Path $SignalFile -Value "SKIP:uventet-sti" -Force
        Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
        exit 0
    }

    # ============================================================
    # DUPLIKAT BEKREFTET - starter reparasjon
    # ============================================================
    Write-EngineLog "========================================="
    Write-EngineLog "DUPLIKAT BEKREFTET - STARTER REPARASJON"
    Write-EngineLog "  Bruker:     $SamAccount"
    Write-EngineLog "  Gammel SID: $OldSid -> $UserProfileBase"
    Write-EngineLog "  Ny SID:     $CurrentSid -> $UserProfileDuped"
    Write-EngineLog "  Maskin:     $env:COMPUTERNAME"
    Write-EngineLog "========================================="

    # ---- Steg 1: Backup gammel ProfileList-noekkel ----
    Write-EngineLog "Steg 1/4: Eksporterer registry-backup"
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
    $Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $BackupFile = Join-Path $BackupDir "$env:COMPUTERNAME-$SamAccount-$Timestamp.reg"
    $RegExport = & reg.exe export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$OldSid" $BackupFile /y 2>&1
    Write-EngineLog "Steg 1/4: Backup lagret: $BackupFile (reg.exe output: $RegExport)"

    # ---- Steg 2: Slett ny SID-noekkel (peker paa .AD) ----
    Write-EngineLog "Steg 2/4: Fjerner ny SID-noekkel ($CurrentSid)"
    $NewSidKeyPath = "$ProfileListReg\$CurrentSid"
    if (Test-Path $NewSidKeyPath) {
        Remove-Item $NewSidKeyPath -Recurse -Force
        Write-EngineLog "Steg 2/4: Fjernet $NewSidKeyPath (pekte paa $UserProfileDuped)"
    }
    else {
        Write-EngineLog "Steg 2/4: $NewSidKeyPath fantes ikke - fortsetter"
    }

    # ---- Steg 3: Kopier gammel SID til ny SID, slett gammel ----
    Write-EngineLog "Steg 3/4: Kopierer $OldSid -> $CurrentSid"
    Copy-Item $OldSidEntry.PSPath "$ProfileListReg\$CurrentSid" -Recurse
    Write-EngineLog "Steg 3/4: Kopi fullfoert, sletter gammel noekkel $OldSid"
    Remove-Item $OldSidEntry.PSPath -Recurse -Force
    Write-EngineLog "Steg 3/4: ProfileList remappet: $OldSid -> $CurrentSid"

    # Verifiser remapping
    $VerifyPath = (Get-ItemProperty "$ProfileListReg\$CurrentSid" -ErrorAction SilentlyContinue).ProfileImagePath
    Write-EngineLog "Steg 3/4: Verifisering: $CurrentSid peker naa paa '$VerifyPath'"

    # ---- Steg 4: Fjern duplikat-profilkatalog ----
    Write-EngineLog "Steg 4/4: Fjerner duplikatprofil $UserProfileDuped"
    $EscapedPath  = $UserProfileDuped -replace '\\', '\\\\'
    $DupedProfile = Get-CimInstance Win32_UserProfile -Filter "LocalPath='$EscapedPath'" -ErrorAction SilentlyContinue

    if ($DupedProfile) {
        Write-EngineLog "Steg 4/4: Fant Win32_UserProfile for $UserProfileDuped - fjerner via CIM"
        Remove-CimInstance -InputObject $DupedProfile -ErrorAction SilentlyContinue
        Write-EngineLog "Steg 4/4: Win32_UserProfile fjernet"
    }
    elseif (Test-Path $UserProfileDuped) {
        Write-EngineLog "Steg 4/4: Ingen Win32_UserProfile funnet - fjerner katalog direkte"
        Remove-Item $UserProfileDuped -Recurse -Force -ErrorAction SilentlyContinue
        Write-EngineLog "Steg 4/4: Katalog fjernet"
    }
    else {
        Write-EngineLog "Steg 4/4: Duplikatkatalog allerede borte"
    }

    # ---- Telemetri og markoerer ----
    Write-EngineLog "Skriver telemetri og markoerer"

    if (-not (Test-Path $CompletedDir)) {
        New-Item -ItemType Directory -Path $CompletedDir -Force | Out-Null
    }

    $HistoryLine = "$SamAccount,$OldSid,$CurrentSid,$env:COMPUTERNAME,$(Get-Date -Format 'o')"
    Add-Content $HistoryFile -Value $HistoryLine -ErrorAction SilentlyContinue
    Write-EngineLog "Historikk skrevet: $HistoryLine"

    Set-Content -Path $UserMarker -Value "OK:$OldSid->${CurrentSid}:$(Get-Date -Format 'o')" -Force
    Write-EngineLog "Completion-markoer skrevet: $UserMarker"

    # ---- Signaler overlay ----
    Set-Content -Path $SignalFile -Value "DONE:$(Get-Date -Format 'o')" -Force
    Write-EngineLog "Signal DONE skrevet: $SignalFile"

    # ---- Rydd opp request-fil ----
    Remove-Item $RequestFile.FullName -Force -ErrorAction SilentlyContinue
    Write-EngineLog "Request-fil fjernet"

    Write-EngineLog "========================================="
    Write-EngineLog "REPARASJON FULLFOERT for $SamAccount"
    Write-EngineLog "  Gammel SID: $OldSid (fjernet)"
    Write-EngineLog "  Ny SID:     $CurrentSid (peker naa paa $UserProfileBase)"
    Write-EngineLog "  Overlay vil logge av brukeren om ~10 sekunder"
    Write-EngineLog "========================================="
    exit 0
}
catch {
    Write-EngineLog "KRITISK FEIL: $($_.Exception.Message)" -Level Error
    Write-EngineLog "Stack trace: $($_.ScriptStackTrace)" -Level Error
    # Signaler overlay slik at brukeren ikke sitter fast
    Set-Content -Path $SignalFile -Value "ERROR:$($_.Exception.Message)" -Force
    Write-EngineLog "Signal ERROR skrevet - overlay vil logge av brukeren"
    exit 1
}
'@

    $EngineFinal = $EngineTemplate.Replace('%%SUFFIX%%', $DomainSuffix)
    Set-Content -Path $EngineScript -Value $EngineFinal -Encoding UTF8 -Force
    Write-InstallLog "Skrevet: $EngineScript"

    # VBS-launcher for Engine: starter PowerShell helt usynlig
    $EngineVbsContent = "CreateObject(""WScript.Shell"").Run ""powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File """"$EngineScript"""""", 0, False"
    Set-Content -Path $EngineLauncher -Value $EngineVbsContent -Encoding ASCII -Force
    Write-InstallLog "Skrevet: $EngineLauncher"

    # ============================================================
    # 5. Opprett scheduled tasks under \ProfileRemediation\
    # ============================================================
    Write-InstallLog "Registrerer scheduled tasks under $TaskPath"

    # Fjern eksisterende (idempotent reinstallasjon)
    Unregister-ScheduledTask -TaskName $TaskNameOverlay -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskNameEngine  -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue

    # --- Task 1: Overlay (brukersesjon, interaktiv, umiddelbart) ---
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
        -Description "Viser statusmelding under profilreparasjon (v$ScriptVersion)" `
        -Force | Out-Null

    Write-InstallLog "Task '$TaskPath$TaskNameOverlay' registrert (brukersesjon, ved logon)"

    # --- Task 2: Engine (SYSTEM, 5 sekunders delay) ---
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
        -Description "Utfoerer profilreparasjon ved logon (v$ScriptVersion)" `
        -Force | Out-Null

    Write-InstallLog "Task '$TaskPath$TaskNameEngine' registrert (SYSTEM, 5s delay)"

    # ============================================================
    # 6. Skriv versjonsmarkoer
    # ============================================================
    Set-Content -Path $VersionFile -Value $ScriptVersion -Encoding UTF8 -Force

    Write-InstallLog "Installasjon fullfoert v$ScriptVersion paa $env:COMPUTERNAME"
    exit 0
}
catch {
    Write-InstallLog "FEIL i installasjon: $($_.Exception.Message)" -Level Error
    exit 1
}
