<#
.SYNOPSIS
  Offline SOC endpoint deployment for Windows.

.DESCRIPTION
  Installs/configures Wazuh Agent and Sysmon without internet access.
  Packages are discovered from the repository packages directory.
  The script also enables core Windows/SOC telemetry, service recovery,
  validates manager connectivity, and writes a deployment report.

.REQUIREMENTS
  Run as Administrator.
  Place a Wazuh MSI in packages\windows\.
  Place Sysmon64.exe and sysmonconfig.xml in packages\windows\sysmon\.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Manager,
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$AgentGroup = "windows,soc",
    [switch]$SkipEnrollment,
    [switch]$SkipSysmon,
    [switch]$SkipFirewallRule,
    [switch]$ForceReconfigure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptRoot
$PackageRoot = Join-Path $RepoRoot 'packages\windows'
$SysmonPackageRoot = Join-Path $PackageRoot 'sysmon'
$StateRoot = 'C:\ProgramData\SOCOfflineDeploy'
$ReportPath = Join-Path $StateRoot ("deployment_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$WazuhPath = 'C:\Program Files (x86)\ossec-agent'
$WazuhConf = Join-Path $WazuhPath 'ossec.conf'

New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null

function Log {
    param([string]$Level,[string]$Message)
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format o),$Level,$Message
    Write-Host $line
    Add-Content -Path $ReportPath -Value $line
}

function Require-Admin {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'Run PowerShell as Administrator.'
    }
}

function Find-OneFile {
    param([string]$Path,[string]$Filter)
    $items = @(Get-ChildItem -Path $Path -Filter $Filter -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    if($items.Count -eq 0){ throw "Required package not found: $Path\$Filter" }
    if($items.Count -gt 1){ Log 'WARN' "Multiple packages match $Filter; selecting $($items[0].Name)." }
    return $items[0].FullName
}

function Test-Port {
    param([int]$Port)
    try { return [bool](Test-NetConnection -ComputerName $Manager -Port $Port -WarningAction SilentlyContinue).TcpTestSucceeded }
    catch { return $false }
}

function Validate-PackageTrust {
    param([string]$Path)
    $hash=(Get-FileHash $Path -Algorithm SHA256).Hash
    Log 'INFO' "SHA256 $([IO.Path]::GetFileName($Path)) = $hash"
    if([IO.Path]::GetExtension($Path) -in @('.msi','.exe')){
        $sig=Get-AuthenticodeSignature $Path
        if($sig.Status -eq 'Valid') { Log 'OK' "Authenticode signature valid for $Path" }
        else { Log 'WARN' "Authenticode signature status for $Path: $($sig.Status). Verify package provenance before production deployment." }
    }
}

function Ensure-Wazuh {
    if(Test-Path (Join-Path $WazuhPath 'wazuh-agent.exe')){
        Log 'OK' 'Wazuh Agent already installed.'
        return
    }
    $msi=Find-OneFile -Path $PackageRoot -Filter 'wazuh-agent*.msi'
    Validate-PackageTrust $msi
    $args=@('/i',"`"$msi`"",'/qn','/norestart',"WAZUH_MANAGER=`"$Manager`"", "WAZUH_REGISTRATION_SERVER=`"$Manager`"", "WAZUH_AGENT_NAME=`"$AgentName`"")
    if($AgentGroup){ $args += "WAZUH_AGENT_GROUP=`"$AgentGroup`"" }
    $p=Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
    if($p.ExitCode -notin @(0,3010)){ throw "Wazuh MSI failed with exit code $($p.ExitCode)" }
    Log 'OK' "Wazuh Agent installed offline from $msi"
}

function Configure-Wazuh {
    if(-not (Test-Path $WazuhPath)){ throw 'Wazuh installation directory not found.' }
    if((Test-Path $WazuhConf) -and -not $ForceReconfigure){
        Copy-Item $WazuhConf "$WazuhConf.bak_$(Get-Date -Format yyyyMMdd_HHmmss)" -Force
    }
    $xml=@"
<ossec_config>
  <client>
    <server><address>$Manager</address><port>1514</port><protocol>tcp</protocol></server>
    <notify_time>10</notify_time><time-reconnect>60</time-reconnect><auto_restart>yes</auto_restart>
    <config-profile>$AgentGroup</config-profile>
  </client>
  <client_buffer><disabled>no</disabled><queue_size>5000</queue_size><events_per_second>500</events_per_second></client_buffer>
  <localfile><location>Security</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>System</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Application</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-Windows Defender/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-TaskScheduler/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-WMI-Activity/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-WinRM/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</location><log_format>eventchannel</log_format></localfile>
  <syscheck>
    <disabled>no</disabled><frequency>43200</frequency><scan_on_start>yes</scan_on_start><alert_new_files>yes</alert_new_files>
    <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\System32\Tasks</directories>
    <directories check_all="yes" realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</windows_registry>
    <ignore>C:\Windows\Temp</ignore><ignore>C:\Windows\Prefetch</ignore><ignore type="sregex">.log$|.tmp$|.etl$</ignore>
  </syscheck>
  <rootcheck><disabled>no</disabled><check_files>yes</check_files><check_trojans>yes</check_trojans><check_dev>yes</check_dev><check_sys>yes</check_sys><check_pids>yes</check_pids><check_ports>yes</check_ports><check_if>yes</check_if><frequency>43200</frequency></rootcheck>
  <sca><enabled>yes</enabled><scan_on_start>yes</scan_on_start><interval>12h</interval></sca>
  <wodle name="syscollector"><disabled>no</disabled><interval>1h</interval><scan_on_start>yes</scan_on_start><hardware>yes</hardware><os>yes</os><network>yes</network><packages>yes</packages><ports all="no">yes</ports><processes>yes</processes><hotfixes>yes</hotfixes></wodle>
</ossec_config>
"@
    Set-Content -Path $WazuhConf -Value $xml -Encoding UTF8
    Log 'OK' 'SOC-oriented ossec.conf written.'
}

function Configure-WindowsTelemetry {
    $subs=@('Logon','Logoff','Account Lockout','User Account Management','Security Group Management','Computer Account Management','Process Creation','Audit Policy Change','Authentication Policy Change','System Integrity','Security System Extension','Sensitive Privilege Use')
    foreach($s in $subs){
        & auditpol.exe /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
    }
    reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
    reg add 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
    reg add 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
    reg add 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' /v '*' /t REG_SZ /d '*' /f | Out-Null
    Log 'OK' 'Windows audit and PowerShell telemetry enabled.'
}

function Ensure-Sysmon {
    if($SkipSysmon){ Log 'WARN' 'Sysmon deployment skipped.'; return }
    $exe=Join-Path $SysmonPackageRoot 'Sysmon64.exe'
    $cfg=Join-Path $SysmonPackageRoot 'sysmonconfig.xml'
    if(-not (Test-Path $exe)){ throw "Missing offline Sysmon executable: $exe" }
    if(-not (Test-Path $cfg)){ throw "Missing Sysmon config: $cfg" }
    Validate-PackageTrust $exe
    $svc=Get-Service Sysmon64 -ErrorAction SilentlyContinue
    if($svc){
        & $exe -c $cfg | Out-Null
        Log 'OK' 'Existing Sysmon configuration updated.'
    } else {
        & $exe -accepteula -i $cfg | Out-Null
        Log 'OK' 'Sysmon installed offline.'
    }
}

function Configure-Recovery {
    $svc=Get-Service WazuhSvc -ErrorAction Stop
    Set-Service WazuhSvc -StartupType Automatic
    sc.exe failure WazuhSvc reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    sc.exe failureflag WazuhSvc 1 | Out-Null
    if((Get-Service Sysmon64 -ErrorAction SilentlyContinue)){ Set-Service Sysmon64 -StartupType Automatic }
    Log 'OK' 'Service startup/recovery configured.'
}

function Ensure-Firewall {
    if($SkipFirewallRule){ return }
    foreach($port in @(1514,1515)){
        $name="SOC Wazuh outbound TCP $port to $Manager"
        if(-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)){
            try { New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $Manager -RemotePort $port -Profile Any | Out-Null }
            catch { Log 'WARN' "Could not create local firewall rule for TCP $port: $($_.Exception.Message)" }
        }
    }
}

function Enroll-Wazuh {
    if($SkipEnrollment){ Log 'WARN' 'Agent enrollment skipped.'; return }
    $auth=Join-Path $WazuhPath 'agent-auth.exe'
    if(-not (Test-Path $auth)){ Log 'WARN' 'agent-auth.exe not found.'; return }
    & $auth -m $Manager -A $AgentName
    if($LASTEXITCODE -ne 0){ Log 'WARN' "agent-auth returned code $LASTEXITCODE" } else { Log 'OK' 'Agent enrollment completed.' }
}

function Validate-Deployment {
    foreach($p in @(1514,1515)){ if(Test-Port $p){Log 'OK' "Manager TCP $p reachable."}else{Log 'WARN' "Manager TCP $p not reachable."} }
    Restart-Service WazuhSvc -Force
    Start-Sleep -Seconds 3
    $svc=Get-Service WazuhSvc
    Log 'INFO' "WazuhSvc status: $($svc.Status)"
    if(-not $SkipSysmon){ $ss=Get-Service Sysmon64 -ErrorAction SilentlyContinue; if($ss){Log 'INFO' "Sysmon64 status: $($ss.Status)"} }
    eventcreate /T INFORMATION /ID 9001 /L APPLICATION /SO SOCOfflineDeploy /D 'WAZUH_READINESS_TEST offline deployment validation' | Out-Null
    Log 'OK' 'Created Application Event ID 9001 readiness marker.'
}

Require-Admin
Log 'INFO' "Starting offline deployment. Manager=$Manager Agent=$AgentName Group=$AgentGroup"
Ensure-Wazuh
Configure-Wazuh
Configure-WindowsTelemetry
Ensure-Sysmon
Configure-Recovery
Ensure-Firewall
Enroll-Wazuh
Validate-Deployment
Log 'OK' "Deployment completed. Report: $ReportPath"
