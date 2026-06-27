# Wazuh Agent Auto Deploy

Production-ready scripts to automatically deploy, configure, harden, and validate Wazuh Agent on:

- Windows
- Linux
- macOS

This repository is designed for SOC/SIEM teams that need Wazuh agents to be:

- Auto-starting after reboot
- Auto-recovering after service failure
- Configured for TCP-based Wazuh Manager communication
- Ready for SOC monitoring
- Collecting important Windows, Linux, and macOS security logs
- Configured with FIM, SCA, Rootcheck, and Syscollector
- Easy to deploy by asking the user for Wazuh Manager IP/FQDN and agent details

---

## Features

### Windows

The Windows deployment script configures:

- Wazuh Agent installation
- Wazuh Manager IP/FQDN
- Agent name
- Agent group/profile
- TCP 1514 communication
- Agent reconnect settings
- Windows service auto-start
- Windows service recovery
- Windows Security/System/Application logs
- PowerShell Operational logs
- Sysmon log channel
- Microsoft Defender logs
- RDP logs
- WMI and WinRM logs
- Task Scheduler logs
- AppLocker logs
- Windows Firewall logs
- DNS Client logs
- Windows audit policy
- PowerShell Script Block Logging
- PowerShell Module Logging
- File Integrity Monitoring
- SCA
- Rootcheck
- Syscollector

### Linux

The Linux deployment script configures:

- Wazuh Agent installation
- Debian/Ubuntu support
- RHEL/CentOS/Rocky/AlmaLinux support
- Wazuh Manager IP/FQDN
- Agent name
- Agent group/profile
- TCP 1514 communication
- Agent reconnect settings
- systemd auto-start
- systemd service recovery
- `/var/log/auth.log`
- `/var/log/secure`
- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/audit/audit.log`
- journald collection
- Apache logs
- Nginx logs
- MySQL/MariaDB/PostgreSQL logs
- Docker logs
- Firewall logs
- Linux auditd rules
- File Integrity Monitoring
- SCA
- Rootcheck
- Syscollector

### macOS

The macOS deployment script configures:

- Wazuh Agent installation
- Wazuh Manager IP/FQDN
- Agent name
- Agent group/profile
- TCP 1514 communication
- Agent reconnect settings
- LaunchDaemon auto-start
- `/var/log/system.log`
- `/var/log/install.log`
- `/var/log/wifi.log`
- `/var/audit/current`
- macOS persistence path monitoring
- File Integrity Monitoring
- SCA
- Rootcheck
- Syscollector

---

## Important Note

These scripts make the Wazuh agent **auto-starting, auto-recovering, and SOC-ready whenever the endpoint and network are available**.

They cannot prevent disconnection when:

- Endpoint is powered off
- Endpoint is sleeping
- Endpoint has no network
- Firewall blocks TCP 1514 or TCP 1515
- Wazuh Manager is unavailable
- Wazuh agent key is invalid
- Agent name or ID is duplicated

---

## Required Ports

| Source | Destination | Port | Protocol | Purpose |
|---|---|---:|---|---|
| Wazuh Agent | Wazuh Manager | 1514 | TCP | Agent event forwarding |
| Wazuh Agent | Wazuh Manager | 1515 | TCP | Agent enrollment |
| Admin/SOC | Wazuh API | 55000 | TCP | Optional API access |

---

## Repository Structure

```text
wazuh-agent-auto-deploy/
├── README.md
├── LICENSE
├── .gitignore
├── deploy-menu.sh
├── configs/
│   ├── ossec-windows-template.conf
│   ├── ossec-linux-template.conf
│   └── ossec-macos-template.conf
├── docs/
│   ├── DEPLOYMENT.md
│   ├── TROUBLESHOOTING.md
│   └── SOC_LOG_SOURCES.md
└── scripts/
    ├── windows/
    │   └── Deploy-Wazuh-Windows.ps1
    ├── linux/
    │   └── deploy-wazuh-linux.sh
    └── macos/
        └── deploy-wazuh-macos.sh
```

---

## Quick Start

### Windows

Open PowerShell as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\windows\Deploy-Wazuh-Windows.ps1
```

The script will ask:

```text
Wazuh Manager IP/FQDN
Agent name
Agent group/profile
Enrollment password, if used
Whether to run agent-auth enrollment
```

---

### Linux

```bash
chmod +x deploy-menu.sh
./deploy-menu.sh
```

Or run directly:

```bash
sudo bash ./scripts/linux/deploy-wazuh-linux.sh
```

---

### macOS

```bash
chmod +x deploy-menu.sh
./deploy-menu.sh
```

Or run directly:

```bash
sudo bash ./scripts/macos/deploy-wazuh-macos.sh
```

---

## Example Inputs

```text
Wazuh Manager Type: FQDN
Wazuh Manager: wazuh-manager.company.local
Agent Name: HR-LAPTOP-01
Agent Group: windows,soc,workstation
Enrollment Password: ********
Run Enrollment: Y
```

or:

```text
Wazuh Manager Type: IP
Wazuh Manager: 10.10.10.50
Agent Name: linux-web-01
Agent Group: linux,soc,webserver
Enrollment Password:
Run Enrollment: Y
```

---

## Validation

### Windows

```powershell
Get-Service WazuhSvc
Test-NetConnection WAZUH_MANAGER_IP_OR_FQDN -Port 1514
Test-NetConnection WAZUH_MANAGER_IP_OR_FQDN -Port 1515
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

### Linux

```bash
sudo systemctl status wazuh-agent
nc -vz WAZUH_MANAGER_IP_OR_FQDN 1514
nc -vz WAZUH_MANAGER_IP_OR_FQDN 1515
sudo tail -n 50 /var/ossec/logs/ossec.log
```

### macOS

```bash
sudo /Library/Ossec/bin/wazuh-control status
nc -vz WAZUH_MANAGER_IP_OR_FQDN 1514
nc -vz WAZUH_MANAGER_IP_OR_FQDN 1515
sudo tail -n 50 /Library/Ossec/logs/ossec.log
```

---

## Recommended GitHub Upload Commands

```bash
git init
git add .
git commit -m "Initial Wazuh agent auto deployment scripts"
git branch -M main
git remote add origin https://github.com/astrax3v2/wazuh-agent-auto-deploy
git push -u origin main
```

---

## Security Recommendation

Before production deployment:

1. Test the scripts in a lab.
2. Confirm Wazuh Manager ports are open.
3. Confirm enrollment password handling policy.
4. Review FIM paths for noise.
5. Confirm Sysmon is installed on Windows endpoints.
6. Confirm auditd is installed on Linux.
7. Validate event ingestion in Wazuh Dashboard.

---

## License

This project is released under the MIT License.
