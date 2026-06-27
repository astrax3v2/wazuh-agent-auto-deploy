# SOC Log Sources

## Windows

| Log Source | Purpose |
|---|---|
| Security | Authentication, account changes, privilege use |
| System | Service changes, driver events, system errors |
| Application | Application errors |
| PowerShell Operational | Script execution |
| Sysmon Operational | Process, network, registry, DNS telemetry |
| Defender Operational | Malware and AV events |
| Task Scheduler | Persistence |
| WMI Activity | Lateral movement |
| WinRM | Remote administration |
| RDP LocalSessionManager | RDP logon/session |
| AppLocker | Application control |
| Firewall | Firewall rule and traffic events |

## Linux

| Log Path | Purpose |
|---|---|
| /var/log/auth.log | SSH/sudo/authentication |
| /var/log/secure | RHEL authentication |
| /var/log/syslog | Debian/Ubuntu system logs |
| /var/log/messages | RHEL system logs |
| /var/log/audit/audit.log | auditd security events |
| /var/log/cron | Scheduled task activity |
| /var/log/nginx/access.log | Web access |
| /var/log/apache2/access.log | Web access |
| /var/lib/docker/containers/*/*-json.log | Container logs |

## macOS

| Log Path | Purpose |
|---|---|
| /var/log/system.log | System events |
| /var/log/install.log | Install events |
| /var/log/wifi.log | Wi-Fi events |
| /var/audit/current | Audit events |
| /Library/Logs/*.log | Application logs |
