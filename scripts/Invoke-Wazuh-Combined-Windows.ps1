<#
.SYNOPSIS
  Combined Wazuh Agent Auto Deploy + Security Recommendation Enforcer - Windows

.DESCRIPTION
  This is a single production-ready Windows script that:
    - Takes Wazuh Manager IP/FQDN from user
    - Takes Agent Name and Group/Profile from user
    - Checks production readiness recommendations
    - Checks Wazuh Manager ports
    - Installs Wazuh Agent if missing
    - Writes SOC-ready ossec.conf
    - Configures Wazuh agent reconnect options
    - Configures WazuhSvc auto-start and auto-recovery
    - Checks enrollment password handling
    - Optionally enrolls the agent
    - Enables Windows audit policy
    - Enables PowerShell logging
    - Checks/optionally installs Sysmon
    - Adds FIM noise-control entries if missing
    - Generates local event ingestion test
    - Restarts Wazuh agent
    - Creates readiness report

.RUN AS
  PowerShell Administrator

.EXAMPLES
  powershell.exe -ExecutionPolicy Bypass -File .\Invoke-Wazuh-Combined-Windows.ps1

  .\Invoke-Wazuh-Combined-Windows.ps1 -Manager 10.10.10.50 -InstallSysmonIfMissing

  .\Invoke-Wazuh-Combined-Windows.ps1 -Manager wazuh-manager.company.local -AgentName HR-LAPTOP-01 -AgentGroup "windows,soc,workstation" -NonInteractive
#>

[CmdletBinding()]
param(
    [string]$Manager,
    [string]$AgentName,
    [string]$AgentGroup,
    [string]$InstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi",
    [switch]$InstallSysmonIfMissing,
    [string]$SysmonConfigPath,
    [switch]$NonInteractive,
    [switch]$SkipApiPortCheck,
    [switch]$SkipEnrollment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Global:Report = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Add-Report {
    param([string]$Status, [string]$Item, [string]$Details)
    $line = "[$Status] $Item - $Details"
    $Global:Report.Add($line) | Out-Null

    switch ($Status) {
        "OK" { Write-Host $line -ForegroundColor Green }
        "FIXED" { Write-Host $line -ForegroundColor Green }
        "WARN" { Write-Host $line -ForegroundColor Yellow }
        "FAIL" { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script as Administrator."
    }
}

function Ask-Required {
    param([string]$Prompt, [string]$Default = "")

    while ($true) {
        if ($Default -ne "") {
            $value = Read-Host "$Prompt [$Default]"
            if ([string]::IsNullOrWhiteSpace($value)) { $value = $Default }
        } else {
            $value = Read-Host $Prompt
        }

        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value.Trim()
        }

        Write-Host "Value cannot be empty." -ForegroundColor Yellow
    }
}

function Confirm-Yes {
    param([string]$Prompt)

    if ($NonInteractive) { return $true }

    $answer = Read-Host "$Prompt (Y/N)"
    return ($answer -match '^(Y|y)$')
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port)

    try {
        $result = Test-NetConnection -ComputerName $HostName -Port $Port -WarningAction SilentlyContinue
        return [bool]$result.TcpTestSucceeded
    } catch {
        return $false
    }
}

function Set-LabTestAcknowledgement {
    Write-Section "1. Lab Test / Production Pilot Acknowledgement"

    $markerDir = "C:\ProgramData\WazuhCombinedDeploy"
    $markerFile = Join-Path $markerDir "lab_test_acknowledged.txt"

    if (Test-Path $markerFile) {
        Add-Report "OK" "Lab acknowledgement" "Marker already exists: $markerFile"
        return
    }

    if ($NonInteractive -or (Confirm-Yes "Confirm this script/configuration has been tested in a lab or approved for production pilot")) {
        New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
        "Acknowledged by $env:USERNAME on $(Get-Date -Format o)" | Set-Content -Path $markerFile -Encoding UTF8
        Add-Report "FIXED" "Lab acknowledgement" "Created marker: $markerFile"
    } else {
        Add-Report "WARN" "Lab acknowledgement" "Not confirmed. Do not mass deploy without lab validation."
    }
}

function Confirm-WazuhPorts {
    param([string]$ManagerAddress)

    Write-Section "2. Wazuh Manager Port Validation"

    $ports = @(1514, 1515)
    if (-not $SkipApiPortCheck) { $ports += 55000 }

    foreach ($port in $ports) {
        if (Test-TcpPort -HostName $ManagerAddress -Port $port) {
            Add-Report "OK" "TCP port $port" "Reachable on $ManagerAddress"
        } else {
            Add-Report "WARN" "TCP port $port" "Not reachable on $ManagerAddress. Check firewall/network path."
        }
    }
}

function Ensure-LocalFirewallRules {
    param([string]$ManagerAddress)

    Write-Section "3. Local Windows Firewall Outbound Rules"

    $ports = @(1514, 1515, 55000)

    foreach ($port in $ports) {
        $ruleName = "Wazuh Outbound TCP $port to $ManagerAddress"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

        if ($existing) {
            Add-Report "OK" "Firewall rule $port" "Already exists."
            continue
        }

        try {
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Direction Outbound `
                -Action Allow `
                -Protocol TCP `
                -RemoteAddress $ManagerAddress `
                -RemotePort $port `
                -Profile Any | Out-Null

            Add-Report "FIXED" "Firewall rule $port" "Created outbound allow rule to $ManagerAddress."
        } catch {
            Add-Report "WARN" "Firewall rule $port" "Could not create local rule: $($_.Exception.Message)"
        }
    }
}

function Check-EnrollmentPasswordPolicy {
    Write-Section "4. Enrollment Password Handling Policy"

    $badPatterns = @(
        "C:\wazuh*password*.txt",
        "C:\ProgramData\*wazuh*password*.txt",
        "$env:TEMP\*wazuh*password*.txt",
        "$env:USERPROFILE\Desktop\*wazuh*password*.txt",
        "$env:USERPROFILE\Downloads\*wazuh*password*.txt",
        "$env:USERPROFILE\Documents\*wazuh*password*.txt"
    )

    $found = @()

    foreach ($pattern in $badPatterns) {
        $items = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
        if ($items) { $found += $items }
    }

    if ($found.Count -eq 0) {
        Add-Report "OK" "Enrollment password files" "No obvious plaintext password files found."
    } else {
        foreach ($file in $found) {
            Add-Report "WARN" "Plaintext password file" "Found: $($file.FullName)"
            if (-not $NonInteractive -and (Confirm-Yes "Remove this file? $($file.FullName)")) {
                Remove-Item -Path $file.FullName -Force
                Add-Report "FIXED" "Plaintext password file" "Removed: $($file.FullName)"
            }
        }
    }

    Add-Report "OK" "Password handling" "Use runtime prompt. Do not hardcode enrollment password in scripts/files."
}

function Install-WazuhAgent {
    param(
        [string]$ManagerAddress,
        [string]$Name,
        [string]$Group
    )

    Write-Section "5. Wazuh Agent Installation"

    $installPath = "C:\Program Files (x86)\ossec-agent"

    if (Test-Path "$installPath\ossec-agent.exe") {
        Add-Report "OK" "Wazuh Agent" "Already installed."
        return
    }

    try {
        $tempMsi = Join-Path $env:TEMP "wazuh-agent.msi"
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $tempMsi

        $msiArgs = @(
            "/i", "`"$tempMsi`"",
            "/q",
            "WAZUH_MANAGER=`"$ManagerAddress`"",
            "WAZUH_AGENT_NAME=`"$Name`"",
            "WAZUH_REGISTRATION_SERVER=`"$ManagerAddress`""
        )

        if (-not [string]::IsNullOrWhiteSpace($Group)) {
            $msiArgs += "WAZUH_AGENT_GROUP=`"$Group`""
        }

        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru

        if ($process.ExitCode -ne 0) {
            throw "MSI installation failed with exit code $($process.ExitCode)"
        }

        Add-Report "FIXED" "Wazuh Agent" "Installed successfully."
    } catch {
        Add-Report "FAIL" "Wazuh Agent installation" $_.Exception.Message
        throw
    }
}

function Write-SocReadyOssecConf {
    param([string]$ManagerAddress, [string]$Profile)

    Write-Section "6. Writing SOC-Ready ossec.conf"

    $confPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

    if (-not (Test-Path (Split-Path $confPath))) {
        throw "Wazuh Agent directory not found."
    }

    if (Test-Path $confPath) {
        $backupPath = "$confPath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item $confPath $backupPath -Force
        Add-Report "OK" "ossec.conf backup" "Backup created: $backupPath"
    }

    $conf = @"
<ossec_config>

  <client>
    <server>
      <address>$ManagerAddress</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <config-profile>$Profile</config-profile>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Core Windows Logs -->
  <localfile><location>Security</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>System</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Application</location><log_format>eventchannel</log_format></localfile>

  <!-- PowerShell -->
  <localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Windows PowerShell</location><log_format>eventchannel</log_format></localfile>

  <!-- Sysmon -->
  <localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>

  <!-- Defender -->
  <localfile><location>Microsoft-Windows-Windows Defender/Operational</location><log_format>eventchannel</log_format></localfile>

  <!-- RDP -->
  <localfile><location>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</location><log_format>eventchannel</log_format></localfile>

  <!-- Persistence and Lateral Movement -->
  <localfile><location>Microsoft-Windows-TaskScheduler/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-WMI-Activity/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-WinRM/Operational</location><log_format>eventchannel</log_format></localfile>

  <!-- App Control and Firewall -->
  <localfile><location>Microsoft-Windows-AppLocker/EXE and DLL</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-AppLocker/MSI and Script</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-Windows Firewall With Advanced Security/Firewall</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>C:\Windows\System32\LogFiles\Firewall\pfirewall.log</location><log_format>syslog</log_format></localfile>

  <!-- DNS and Certificate -->
  <localfile><location>Microsoft-Windows-DNS-Client/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-CAPI2/Operational</location><log_format>eventchannel</log_format></localfile>

  <!-- Domain Controller Optional Channels -->
  <localfile><location>Directory Service</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>DNS Server</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>DFS Replication</location><log_format>eventchannel</log_format></localfile>

  <!-- Wazuh Internal Log -->
  <localfile><location>C:\Program Files (x86)\ossec-agent\ossec.log</location><log_format>syslog</log_format></localfile>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>

    <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\System32\Tasks</directories>
    <directories check_all="yes" realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories check_all="yes" realtime="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\System32\GroupPolicy</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\SysWOW64\GroupPolicy</directories>

    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry arch="both">HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</windows_registry>

    <!-- FIM Noise Controls -->
    <ignore>C:\Windows\Temp</ignore>
    <ignore>C:\Windows\Prefetch</ignore>
    <ignore>C:\ProgramData\Microsoft\Windows Defender\Scans</ignore>
    <ignore type="sregex">.log$|.tmp$|.etl$</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
  </rootcheck>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
    <hotfixes>yes</hotfixes>
  </wodle>

  <active-response>
    <disabled>no</disabled>
  </active-response>

</ossec_config>
"@

    Set-Content -Path $confPath -Value $conf -Encoding UTF8
    Add-Report "FIXED" "ossec.conf" "SOC-ready configuration written."
    Add-Report "WARN" "FIM review" "Review FIM noise after 24-48 hours in Wazuh Dashboard."
}

function Ensure-WindowsAuditPolicy {
    Write-Section "7. Windows Audit Policy and PowerShell Logging"

    $subcategories = @(
        "Logon",
        "Logoff",
        "Account Lockout",
        "User Account Management",
        "Security Group Management",
        "Computer Account Management",
        "Process Creation",
        "Directory Service Changes",
        "Audit Policy Change",
        "Authentication Policy Change",
        "System Integrity",
        "Security System Extension",
        "Sensitive Privilege Use"
    )

    foreach ($sub in $subcategories) {
        try {
            auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
            Add-Report "FIXED" "Audit policy" "Enabled success/failure for $sub"
        } catch {
            Add-Report "WARN" "Audit policy" "Could not enable $sub"
        }
    }

    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f | Out-Null

    Add-Report "FIXED" "PowerShell logging" "Script Block and Module Logging enabled."
}

function New-MinimalSysmonConfig {
    param([string]$Path)

    $xml = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="exclude">
      <Image condition="is">C:\Windows\System32\conhost.exe</Image>
    </ProcessCreate>
    <NetworkConnect onmatch="exclude" />
    <DnsQuery onmatch="exclude" />
    <DriverLoad onmatch="exclude" />
    <ProcessAccess onmatch="exclude" />
    <RegistryEvent onmatch="exclude" />
    <FileCreate onmatch="exclude">
      <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
'@

    Set-Content -Path $Path -Value $xml -Encoding UTF8
}

function Ensure-SysmonInstalled {
    Write-Section "8. Sysmon Check and Optional Installation"

    $services = Get-Service -Name "Sysmon*", "Sysmon64*" -ErrorAction SilentlyContinue

    if ($services) {
        Add-Report "OK" "Sysmon" "Sysmon service found."
        return
    }

    Add-Report "WARN" "Sysmon" "Sysmon service not found."

    if (-not $InstallSysmonIfMissing -and -not (Confirm-Yes "Install Sysmon now?")) {
        Add-Report "WARN" "Sysmon" "Skipped. Install Sysmon for process/network/DNS telemetry."
        return
    }

    try {
        $workDir = "C:\ProgramData\WazuhCombinedDeploy\Sysmon"
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null

        $zipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
        $zipPath = Join-Path $workDir "Sysmon.zip"
        $extractPath = Join-Path $workDir "Extracted"

        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        $sysmonExe = Join-Path $extractPath "Sysmon64.exe"
        if (-not (Test-Path $sysmonExe)) { $sysmonExe = Join-Path $extractPath "Sysmon.exe" }

        if (-not (Test-Path $sysmonExe)) { throw "Sysmon executable not found after extraction." }

        if ([string]::IsNullOrWhiteSpace($SysmonConfigPath) -or -not (Test-Path $SysmonConfigPath)) {
            $SysmonConfigPath = Join-Path $workDir "sysmon-minimal-soc.xml"
            New-MinimalSysmonConfig -Path $SysmonConfigPath
            Add-Report "FIXED" "Sysmon config" "Generated minimal config: $SysmonConfigPath"
        }

        & $sysmonExe -accepteula -i $SysmonConfigPath
        Add-Report "FIXED" "Sysmon" "Installed using config: $SysmonConfigPath"
    } catch {
        Add-Report "WARN" "Sysmon installation" "Failed: $($_.Exception.Message)"
    }
}

function Configure-ServiceRecovery {
    Write-Section "9. WazuhSvc Auto-Start and Recovery"

    $svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue

    if (-not $svc) {
        Add-Report "WARN" "WazuhSvc" "Service not found."
        return
    }

    try {
        Set-Service -Name WazuhSvc -StartupType Automatic
        sc.exe failure WazuhSvc reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
        sc.exe config WazuhSvc start= auto | Out-Null
        Add-Report "FIXED" "WazuhSvc recovery" "Automatic startup and restart-on-failure configured."
    } catch {
        Add-Report "WARN" "WazuhSvc recovery" $_.Exception.Message
    }
}

function Enroll-AgentIfRequested {
    param([string]$ManagerAddress, [string]$Name)

    Write-Section "10. Agent Enrollment"

    if ($SkipEnrollment) {
        Add-Report "WARN" "Agent enrollment" "Skipped by parameter."
        return
    }

    if (-not $NonInteractive) {
        if (-not (Confirm-Yes "Run agent-auth enrollment now?")) {
            Add-Report "WARN" "Agent enrollment" "Skipped by user."
            return
        }
    }

    $agentAuth = "C:\Program Files (x86)\ossec-agent\agent-auth.exe"

    if (-not (Test-Path $agentAuth)) {
        Add-Report "WARN" "agent-auth" "agent-auth.exe not found."
        return
    }

    if ($NonInteractive) {
        & $agentAuth -m $ManagerAddress -A $Name
        Add-Report "FIXED" "Agent enrollment" "agent-auth executed without password."
        return
    }

    $password = Read-Host "Enter enrollment password if used, otherwise press Enter"

    if ([string]::IsNullOrWhiteSpace($password)) {
        & $agentAuth -m $ManagerAddress -A $Name
    } else {
        & $agentAuth -m $ManagerAddress -A $Name -P $password
    }

    Add-Report "FIXED" "Agent enrollment" "agent-auth executed."
}

function Generate-TestEvent {
    Write-Section "11. Event Ingestion Validation Test"

    try {
        eventcreate /ID 9001 /L APPLICATION /T INFORMATION /SO WazuhReadiness /D "WAZUH_READINESS_TEST generated at $(Get-Date -Format o)" | Out-Null
        Add-Report "FIXED" "Test event" "Generated Windows Application event ID 9001 source WazuhReadiness."
        Add-Report "WARN" "Dashboard validation" "Search Wazuh Dashboard for WAZUH_READINESS_TEST or WazuhReadiness."
    } catch {
        Add-Report "WARN" "Test event" "Could not generate event: $($_.Exception.Message)"
    }
}

function Restart-And-Validate {
    Write-Section "12. Restart and Validate Wazuh Agent"

    $svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue

    if (-not $svc) {
        Add-Report "WARN" "WazuhSvc" "Service not found after deployment."
        return
    }

    try {
        Restart-Service WazuhSvc -Force
        Start-Sleep -Seconds 5
        $svc = Get-Service -Name WazuhSvc
        Add-Report "FIXED" "WazuhSvc" "Restarted. Status: $($svc.Status)"

        $logPath = "C:\Program Files (x86)\ossec-agent\ossec.log"
        if (Test-Path $logPath) {
            Add-Report "OK" "Agent log" "Last log lines available at $logPath"
            Get-Content $logPath -Tail 30 -ErrorAction SilentlyContinue
        }
    } catch {
        Add-Report "WARN" "WazuhSvc restart" $_.Exception.Message
    }
}

function Save-Report {
    Write-Section "Final Combined Deployment Report"

    $reportDir = "C:\ProgramData\WazuhCombinedDeploy"
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    $reportPath = Join-Path $reportDir "wazuh_combined_deployment_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $Global:Report | Set-Content -Path $reportPath -Encoding UTF8

    foreach ($line in $Global:Report) { Write-Host $line }

    Write-Host ""
    Write-Host "Report saved to: $reportPath" -ForegroundColor Cyan
}

function Main {
    Assert-Admin

    Write-Section "Combined Wazuh Agent Auto Deploy + Security Recommendation Enforcer - Windows"

    if ([string]::IsNullOrWhiteSpace($Manager)) {
        if ($NonInteractive) { throw "Manager is required in non-interactive mode." }
        $Manager = Ask-Required "Enter Wazuh Manager IP/FQDN"
    }

    if ([string]::IsNullOrWhiteSpace($AgentName)) {
        $AgentName = if ($NonInteractive) { $env:COMPUTERNAME } else { Ask-Required "Enter Agent Name" $env:COMPUTERNAME }
    }

    if ([string]::IsNullOrWhiteSpace($AgentGroup)) {
        $AgentGroup = if ($NonInteractive) { "windows,soc" } else {
            $g = Read-Host "Enter Agent Group/Profile [windows,soc]"
            if ([string]::IsNullOrWhiteSpace($g)) { "windows,soc" } else { $g }
        }
    }

    Set-LabTestAcknowledgement
    Confirm-WazuhPorts -ManagerAddress $Manager
    Ensure-LocalFirewallRules -ManagerAddress $Manager
    Check-EnrollmentPasswordPolicy
    Install-WazuhAgent -ManagerAddress $Manager -Name $AgentName -Group $AgentGroup
    Write-SocReadyOssecConf -ManagerAddress $Manager -Profile $AgentGroup
    Ensure-WindowsAuditPolicy
    Ensure-SysmonInstalled
    Configure-ServiceRecovery
    Enroll-AgentIfRequested -ManagerAddress $Manager -Name $AgentName
    Generate-TestEvent
    Restart-And-Validate
    Save-Report
}

try {
    Main
} catch {
    Add-Report "FAIL" "Script execution" $_.Exception.Message
    Save-Report
    exit 1
}
