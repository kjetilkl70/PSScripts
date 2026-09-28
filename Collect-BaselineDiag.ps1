<#
.SYNOPSIS
    Collects firewall, policy and event-log evidence for troubleshooting connectivity
    loss after applying the Microsoft Security Baselines.

.DESCRIPTION
    Run elevated locally:
        powershell.exe -ExecutionPolicy Bypass -File .\Collect-BaselineDiag.ps1
    Or deploy via Intune as a Platform script / Remediation detection script
    (Run as logged-on user = No, 64-bit = Yes). It then runs as SYSTEM, no local admin needed.

    Output: a timestamped folder under $OutRoot plus a .zip, readable by $GrantReadTo.
    Nothing on the machine is changed apart from creating that folder.

    Collected:
      1. Firewall     - profile config, all rules, netsh dump, pfirewall.log (+ .old) copies
      2. Event logs   - System, Security, Application, Firewall, SMBClient, NTLM, Kerberos,
                        GroupPolicy, DNS-Client, PrintService, RDP client (.evtx exports)
      3. Policy       - gpresult (HTML + XML), secedit export, auditpol, registry keys that the
                        baseline touches (LSA/NTLM, SMB signing, Kerberos etypes, Schannel, LLMNR, NetBT)
      4. Network      - ipconfig, adapters, DNS servers, SMB client config, connection profiles
      5. Summary.txt  - DROP lines in the date window (optionally filtered on the server),
                        top blocked destinations, and the relevant events in the window
#>

# ======================= SETTINGS - edit before running =======================
$StartDate   = '2026-08-20'   # start of the window you care about (date of the failed test)
$EndDate     = '2026-09-05'   # end of the window
$ServerHint  = ''             # server IP or hostname, e.g. '10.20.30.40' - optional, narrows the summary
$OutRoot     = 'C:\Users\Public\BaselineDiag'   # where the output lands
$GrantReadTo = 'BUILTIN\Users' # who gets read access to the output ('' = don't touch ACLs)
$UploadUrl   = ''             # optional Azure Blob *container* SAS URL to upload the zip to
# ============================================================================

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$ts  = Get-Date -Format 'yyyyMMdd-HHmmss'
$Out = Join-Path $OutRoot "$env:COMPUTERNAME-$ts"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$LogFile = Join-Path $Out '_collector.log'

function Log($msg) {
    $line = "{0:yyyy-MM-dd HH:mm:ss}  {1}" -f (Get-Date), $msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}
function Run-Cmd($name, [scriptblock]$sb) {
    try {
        $r = & $sb 2>&1
        $r | Out-File -FilePath (Join-Path $Out "$name.txt") -Width 400 -Encoding UTF8
        Log "OK   $name"
    } catch { Log "FAIL $name : $($_.Exception.Message)" }
}

Log "Collector started on $env:COMPUTERNAME as $env:USERNAME (elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')))"
Log "Window: $StartDate -> $EndDate   ServerHint: '$ServerHint'"

# ----------------------------------------------------------------------------
# 1. FIREWALL
# ----------------------------------------------------------------------------
$fwDir = Join-Path $Out '1-Firewall'; New-Item -ItemType Directory -Path $fwDir -Force | Out-Null

Run-Cmd '1-Firewall\profiles' {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
        AllowLocalFirewallRules, AllowLocalIPsecRules, NotifyOnListen,
        LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked, LogIgnored | Format-List
}
Run-Cmd '1-Firewall\netsh-allprofiles' { netsh advfirewall show allprofiles }
Run-Cmd '1-Firewall\netsh-global'      { netsh advfirewall show global }
Run-Cmd '1-Firewall\netsh-consec'      { netsh advfirewall consec show rule name=all }

try {
    Get-NetFirewallRule | Where-Object Enabled -eq 'True' |
        Select-Object Name, DisplayName, Direction, Action, Profile, Enabled, PolicyStoreSource, PolicyStoreSourceType, Group |
        Export-Csv -Path (Join-Path $fwDir 'rules-enabled.csv') -NoTypeInformation -Encoding UTF8
    Log 'OK   1-Firewall\rules-enabled.csv'
} catch { Log "FAIL rules export: $($_.Exception.Message)" }

# Copy every firewall log the profiles point at, plus the default folder (incl. .old rotations)
$fwLogPaths = @("$env:SystemRoot\System32\LogFiles\Firewall")
try {
    Get-NetFirewallProfile | ForEach-Object {
        $p = [Environment]::ExpandEnvironmentVariables($_.LogFileName)
        if ($p) { $fwLogPaths += (Split-Path $p -Parent) }
    }
} catch {}
$fwLogPaths | Sort-Object -Unique | ForEach-Object {
    if (Test-Path $_) {
        try {
            Get-ChildItem $_ -File | ForEach-Object {
                Copy-Item $_.FullName -Destination (Join-Path $fwDir $_.Name) -Force
                Log "OK   copied $($_.FullName) ($([math]::Round($_.Length/1KB)) KB, modified $($_.LastWriteTime))"
            }
        } catch { Log "FAIL copying from $_ : $($_.Exception.Message)" }
    } else { Log "WARN firewall log folder not found: $_" }
}

# ----------------------------------------------------------------------------
# 2. EVENT LOGS
# ----------------------------------------------------------------------------
$evDir = Join-Path $Out '2-EventLogs'; New-Item -ItemType Directory -Path $evDir -Force | Out-Null
$logs = @(
    'System', 'Security', 'Application',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity',
    'Microsoft-Windows-SMBClient/Connectivity',
    'Microsoft-Windows-SMBClient/Security',
    'Microsoft-Windows-SMBClient/Operational',
    'Microsoft-Windows-NTLM/Operational',
    'Microsoft-Windows-Kerberos/Operational',
    'Microsoft-Windows-GroupPolicy/Operational',
    'Microsoft-Windows-DNS-Client/Operational',
    'Microsoft-Windows-NetworkProfile/Operational',
    'Microsoft-Windows-PrintService/Admin',
    'Microsoft-Windows-TerminalServices-RDPClient/Operational',
    'Microsoft-Windows-LSA/Operational',
    'Microsoft-Windows-WFP/Operational'
)
foreach ($l in $logs) {
    $file = Join-Path $evDir (($l -replace '[/\\ ]', '_') + '.evtx')
    $r = & wevtutil.exe epl "$l" "$file" /ow:true 2>&1
    if ($LASTEXITCODE -eq 0) { Log "OK   exported $l" } else { Log "WARN $l : $r" }
}
Run-Cmd '2-EventLogs\log-status' {
    foreach ($l in $logs) { "==== $l"; wevtutil.exe gl "$l" 2>&1; "" }
}

# ----------------------------------------------------------------------------
# 3. POLICY
# ----------------------------------------------------------------------------
$polDir = Join-Path $Out '3-Policy'; New-Item -ItemType Directory -Path $polDir -Force | Out-Null

& gpresult.exe /scope:computer /h (Join-Path $polDir 'gpresult.html') /f 2>&1 | Out-Null;  Log "gpresult html exit $LASTEXITCODE"
& gpresult.exe /scope:computer /x (Join-Path $polDir 'gpresult.xml')  /f 2>&1 | Out-Null;  Log "gpresult xml  exit $LASTEXITCODE"
& secedit.exe /export /cfg (Join-Path $polDir 'secedit-export.inf') /quiet 2>&1 | Out-Null; Log "secedit exit $LASTEXITCODE"
Run-Cmd '3-Policy\auditpol' { auditpol.exe /get /category:* }

# Registry keys the baselines touch that commonly break server connectivity
$regKeys = @(
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',                                   # LmCompatibilityLevel, RestrictNTLM, NtlmMinClientSec, RunAsPPL
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',         # RequireSecuritySignature, AllowInsecureGuestAuth
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation',
    'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10',                             # SMB1
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters',  # SupportedEncryptionTypes
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL',            # TLS versions/ciphers
    'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',                       # EnableMulticast (LLMNR)
    'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters',                     # NetBIOS
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc',                             # RestrictRemoteClients
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers',
    'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy',
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall',
    'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device',                        # MDM/Intune-delivered policy
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
)
foreach ($k in $regKeys) {
    $f = Join-Path $polDir (($k -replace '[\\:]', '_') + '.reg')
    $r = & reg.exe export "$k" "$f" /y 2>&1
    if ($LASTEXITCODE -eq 0) { Log "OK   reg $k" } else { Log "WARN reg $k : not present" }
}

# ----------------------------------------------------------------------------
# 4. NETWORK
# ----------------------------------------------------------------------------
$netDir = Join-Path $Out '4-Network'; New-Item -ItemType Directory -Path $netDir -Force | Out-Null
Run-Cmd '4-Network\ipconfig-all'        { ipconfig.exe /all }
Run-Cmd '4-Network\adapters'            { Get-NetAdapter | Format-List; Get-NetIPConfiguration -Detailed | Format-List }
Run-Cmd '4-Network\dns-servers'         { Get-DnsClientServerAddress | Format-Table -AutoSize; Get-DnsClientGlobalSetting | Format-List }
Run-Cmd '4-Network\connection-profiles' { Get-NetConnectionProfile | Format-List }
Run-Cmd '4-Network\smb-client-config'   { Get-SmbClientConfiguration | Format-List }
Run-Cmd '4-Network\netbt'               { nbtstat.exe -n; Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description, TcpipNetbiosOptions | Format-Table -AutoSize }
Run-Cmd '4-Network\hosts-file'          { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

# ----------------------------------------------------------------------------
# 5. SUMMARY for the date window
# ----------------------------------------------------------------------------
$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("BASELINE CONNECTIVITY DIAG SUMMARY  -  $env:COMPUTERNAME  -  generated $(Get-Date)")
$summary.Add("Window: $StartDate to $EndDate   Server filter: '$ServerHint'")
$summary.Add(('=' * 100))

try { $winStart = [datetime]$StartDate; $winEnd = ([datetime]$EndDate).AddDays(1) } catch { $winStart = (Get-Date).AddDays(-60); $winEnd = Get-Date }

# --- 5a. Firewall DROP lines
$summary.Add(""); $summary.Add("---- FIREWALL DROP entries in window (pfirewall.log format: date time action proto src-ip dst-ip src-port dst-port ...)")
$drops = @()
Get-ChildItem $fwDir -Filter '*.log*' -File -ErrorAction SilentlyContinue | ForEach-Object {
    $file = $_.Name
    try {
        Get-Content $_.FullName -ErrorAction Stop | ForEach-Object {
            if ($_ -match '^\d{4}-\d{2}-\d{2} ') {
                $f = $_ -split ' '
                try { $d = [datetime]("$($f[0]) $($f[1])") } catch { return }
                if ($d -ge $winStart -and $d -lt $winEnd -and $f[2] -eq 'DROP') {
                    if (-not $ServerHint -or $_ -like "*$ServerHint*") {
                        $drops += [pscustomobject]@{ File=$file; Time=$d; Proto=$f[3]; Src=$f[4]; Dst=$f[5]; SrcPort=$f[6]; DstPort=$f[7]; Dir=$f[-1]; Raw=$_ }
                    }
                }
            }
        }
    } catch {}
}
if ($drops.Count -eq 0) {
    $summary.Add("No DROP entries found in the window" + $(if ($ServerHint) { " matching '$ServerHint'" }) + ". Check the log's first/last timestamps below to see if the window rolled out of the log.")
} else {
    $summary.Add("Total DROPs in window: $($drops.Count)")
    $summary.Add(""); $summary.Add("Top destinations (Dst:DstPort/Proto Dir):")
    $drops | Group-Object { "$($_.Dst):$($_.DstPort)/$($_.Proto) $($_.Dir)" } | Sort-Object Count -Descending | Select-Object -First 30 |
        ForEach-Object { $summary.Add(("  {0,6}  {1}" -f $_.Count, $_.Name)) }
    $summary.Add(""); $summary.Add("Top sources (Src Dir):")
    $drops | Group-Object { "$($_.Src) $($_.Dir)" } | Sort-Object Count -Descending | Select-Object -First 15 |
        ForEach-Object { $summary.Add(("  {0,6}  {1}" -f $_.Count, $_.Name)) }
    $summary.Add(""); $summary.Add("First 100 DROP lines in window:")
    $drops | Sort-Object Time | Select-Object -First 100 | ForEach-Object { $summary.Add("  " + $_.Raw) }
    $drops | Export-Csv (Join-Path $Out 'drops-in-window.csv') -NoTypeInformation -Encoding UTF8
}
# log coverage
Get-ChildItem $fwDir -Filter '*.log*' -File -ErrorAction SilentlyContinue | ForEach-Object {
    $lines = Get-Content $_.FullName -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\d{4}-' }
    if ($lines) { $summary.Add("Log coverage $($_.Name): $($lines[0].Substring(0,19))  ->  $($lines[-1].Substring(0,19))  ($($lines.Count) entries)") }
    else        { $summary.Add("Log coverage $($_.Name): no entries") }
}

# --- 5b. Relevant events in window
function Add-Events($title, $hash, $max = 200) {
    $summary.Add(""); $summary.Add("---- $title")
    $hash['StartTime'] = $winStart; $hash['EndTime'] = $winEnd
    try {
        $ev = Get-WinEvent -FilterHashtable $hash -MaxEvents $max -ErrorAction Stop | Sort-Object TimeCreated
        if (-not $ev) { $summary.Add("  (none)"); return }
        $summary.Add("  $($ev.Count) event(s) (showing up to $max)")
        foreach ($e in $ev) {
            $m = ($e.Message -replace '\s+', ' ')
            if ($m.Length -gt 600) { $m = $m.Substring(0, 600) + ' ...' }
            $summary.Add(("  {0:yyyy-MM-dd HH:mm:ss}  [{1}] {2}/{3}: {4}" -f $e.TimeCreated, $e.LevelDisplayName, $e.ProviderName, $e.Id, $m))
        }
    } catch { $summary.Add("  (none / log unavailable: $($_.Exception.Message))") }
}
Add-Events 'Group Policy processing (when did the baseline land?)'  @{ LogName='Microsoft-Windows-GroupPolicy/Operational'; Id=1500,1501,1502,1503,4016,5016,7016,8004,8005 } 100
Add-Events 'Windows Firewall policy/rule changes'                    @{ LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' } 150
Add-Events 'SMB client - connectivity'                               @{ LogName='Microsoft-Windows-SMBClient/Connectivity' }
Add-Events 'SMB client - security (signing / guest / auth)'          @{ LogName='Microsoft-Windows-SMBClient/Security' }
Add-Events 'SMB client - operational'                                @{ LogName='Microsoft-Windows-SMBClient/Operational'; Level=1,2,3 }
Add-Events 'Security - logon failures & NTLM (4625/4776) and WFP blocks (5152/5157)' @{ LogName='Security'; Id=4625,4776,5152,5157 }
Add-Events 'NTLM operational (only if auditing was enabled)'         @{ LogName='Microsoft-Windows-NTLM/Operational' }
Add-Events 'Kerberos operational (only if enabled)'                  @{ LogName='Microsoft-Windows-Kerberos/Operational' }
Add-Events 'System - Schannel / TLS'                                 @{ LogName='System'; ProviderName='Schannel' }
Add-Events 'System - errors & warnings'                              @{ LogName='System'; Level=1,2,3 } 300
Add-Events 'DNS client - name resolution failures'                   @{ LogName='Microsoft-Windows-DNS-Client/Operational'; Level=1,2,3 }
Add-Events 'Network profile changes (domain/private/public)'         @{ LogName='Microsoft-Windows-NetworkProfile/Operational'; Id=10000,10001,4004 }

# --- 5c. Key settings at a glance
$summary.Add(""); $summary.Add("---- KEY SETTINGS NOW IN FORCE (from registry)")
$checks = @(
    @{ N='LmCompatibilityLevel (5 = NTLMv2 only, refuse LM/NTLM)';  P='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                              V='LmCompatibilityLevel' },
    @{ N='RestrictSendingNTLMTraffic (2 = deny all)';               P='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0';                       V='RestrictSendingNTLMTraffic' },
    @{ N='NtlmMinClientSec (0x20080000 = NTLMv2 + 128-bit)';        P='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0';                       V='NtlmMinClientSec' },
    @{ N='RunAsPPL (LSA protection)';                               P='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                              V='RunAsPPL' },
    @{ N='SMB client RequireSecuritySignature';                     P='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters';    V='RequireSecuritySignature' },
    @{ N='SMB client AllowInsecureGuestAuth';                       P='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters';    V='AllowInsecureGuestAuth' },
    @{ N='SMB1 (mrxsmb10 Start; 4 = disabled)';                     P='HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10';                        V='Start' },
    @{ N='Kerberos SupportedEncryptionTypes (0x18 = AES only, no RC4)'; P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; V='SupportedEncryptionTypes' },
    @{ N='LLMNR EnableMulticast (0 = disabled)';                    P='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient';                  V='EnableMulticast' },
    @{ N='RPC RestrictRemoteClients (1 = authenticated only)';      P='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc';                        V='RestrictRemoteClients' },
    @{ N='Print RpcAuthnLevelPrivacyEnabled';                       P='HKLM:\SYSTEM\CurrentControlSet\Control\Print';                            V='RpcAuthnLevelPrivacyEnabled' }
)
foreach ($c in $checks) {
    $val = try { (Get-ItemProperty -Path $c.P -Name $c.V -ErrorAction Stop).($c.V) } catch { '(not set)' }
    if ($val -is [int]) { $val = "$val (0x{0:X})" -f $val }
    $summary.Add(("  {0,-65} {1}" -f $c.N, $val))
}
try {
    $summary.Add(""); $summary.Add("---- FIREWALL PROFILES NOW")
    Get-NetFirewallProfile | ForEach-Object {
        $summary.Add(("  {0,-8} Enabled={1} Inbound={2} Outbound={3} LocalRules={4} Log={5} LogBlocked={6}" -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction,$_.AllowLocalFirewallRules,$_.LogFileName,$_.LogBlocked))
    }
} catch {}

$summary | Out-File -FilePath (Join-Path $Out 'SUMMARY.txt') -Encoding UTF8 -Width 400
Log 'OK   SUMMARY.txt written'

# ----------------------------------------------------------------------------
# 6. ACL, ZIP, optional upload
# ----------------------------------------------------------------------------
if ($GrantReadTo) {
    try { & icacls.exe "$OutRoot" /grant "${GrantReadTo}:(OI)(CI)RX" /T /Q 2>&1 | Out-Null; Log "OK   granted read to $GrantReadTo on $OutRoot" }
    catch { Log "WARN icacls: $($_.Exception.Message)" }
}

$zip = "$Out.zip"
try {
    Compress-Archive -Path "$Out\*" -DestinationPath $zip -Force
    Log "OK   zipped -> $zip ($([math]::Round((Get-Item $zip).Length/1MB,1)) MB)"
} catch { Log "FAIL zip: $($_.Exception.Message)" }

if ($UploadUrl -and (Test-Path $zip)) {
    try {
        $blobName = Split-Path $zip -Leaf
        $uri = $UploadUrl -replace '\?', "/$blobName`?"
        Invoke-WebRequest -Uri $uri -Method Put -InFile $zip -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -UseBasicParsing | Out-Null
        Log "OK   uploaded $blobName"
    } catch { Log "FAIL upload: $($_.Exception.Message)" }
}

Log "Done. Output folder: $Out"
Write-Output "Collection complete: $zip"
exit 0
