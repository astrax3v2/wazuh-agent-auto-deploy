# Offline SOC Agent Deployment Runbook

## 1. Purpose

This runbook describes how to deploy Wazuh Agent and supporting endpoint telemetry in restricted or air-gapped environments where endpoints do not have internet access.

Supported deployment paths:

- Windows: Wazuh Agent + Sysmon + Windows audit policy + PowerShell logging + FIM/SCA/Syscollector.
- Debian/Ubuntu: Wazuh Agent + auditd integration when auditd is available.
- RHEL/CentOS/Rocky/AlmaLinux: Wazuh Agent + auditd integration when auditd is available.

The deployment scripts do not download packages from the internet.

---

## 2. Prepare the Offline Bundle

From a controlled internet-connected staging workstation, download approved packages from the official vendor sources.

### Windows

Place under:

```text
packages/windows/
  wazuh-agent-<version>.msi
  sysmon/
    Sysmon64.exe
    sysmonconfig.xml
```

Use `configs/sysmonconfig-soc.xml` as the baseline `sysmonconfig.xml`, or replace it with your internally approved Sysmon configuration.

### Debian/Ubuntu

```text
packages/linux/debian/
  wazuh-agent_<version>_amd64.deb
```

If the target server does not already contain required operating-system dependencies, collect the dependency `.deb` files from a system matching the target OS release and architecture and place them under:

```text
packages/linux/debian/prereqs/
```

### RHEL-family

```text
packages/linux/rhel/
  wazuh-agent-<version>.x86_64.rpm
```

Place any required OS dependency RPMs under:

```text
packages/linux/rhel/prereqs/
```

Do not assume packages collected for one major OS version will work on another.

---

## 3. Package Integrity

Before moving the bundle into production:

1. Validate the package publisher/signature on the internet-connected staging host.
2. Calculate SHA-256 hashes.
3. Record hashes in `packages/SHA256SUMS.txt`.
4. Transfer the bundle using an approved method.
5. Calculate hashes again after transfer.
6. Investigate any mismatch before installation.

Windows:

```powershell
Get-FileHash .\packages\windows\wazuh-agent-*.msi -Algorithm SHA256
Get-FileHash .\packages\windows\sysmon\Sysmon64.exe -Algorithm SHA256
Get-AuthenticodeSignature .\packages\windows\sysmon\Sysmon64.exe
```

Linux:

```bash
sha256sum packages/linux/debian/*.deb
sha256sum packages/linux/rhel/*.rpm
```

Never copy enrollment passwords, API credentials, private keys, or reusable administrative credentials into the package bundle.

---

## 4. Network Requirements

Endpoint to Wazuh Manager:

| Port | Protocol | Purpose |
|---|---|---|
| 1514 | TCP | Agent event communication |
| 1515 | TCP | Agent enrollment/registration |
| 55000 | TCP | Wazuh API; not normally required from endpoints |

Only permit the flows actually required by your architecture. In most endpoint deployments, TCP 1514 and 1515 are sufficient.

Verify routing, firewall policy, DNS resolution if FQDN is used, and time synchronization before deployment.

---

## 5. Windows Deployment

Run PowerShell as Administrator from the repository root:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\Invoke-SOC-Offline-Windows.ps1 `
  -Manager 10.10.10.50 `
  -AgentName SERVER01 `
  -AgentGroup "windows,soc,server"
```

For an Active Directory Domain Controller, use a dedicated group/profile such as:

```powershell
-AgentGroup "windows,soc,domain-controller"
```

The script performs:

- Local Wazuh MSI discovery and installation.
- SHA-256 calculation and Authenticode status reporting.
- Wazuh configuration backup before replacement.
- Wazuh log collection for Windows core security channels.
- PowerShell Script Block and Module Logging enablement.
- Windows advanced audit policy enablement.
- Sysmon local installation/configuration.
- FIM, SCA and Syscollector enablement.
- Wazuh service automatic startup and restart-on-failure.
- TCP 1514/1515 connectivity validation.
- Agent enrollment unless `-SkipEnrollment` is specified.
- Local readiness Event ID 9001 generation.

Reports are written to:

```text
C:\ProgramData\SOCOfflineDeploy\
```

---

## 6. Linux Deployment

Debian/Ubuntu/RHEL-family:

```bash
sudo bash scripts/invoke-soc-offline-linux.sh \
  --manager 10.10.10.50 \
  --agent-name linux-web-01 \
  --agent-group linux,soc,server
```

The script performs:

- OS-family detection.
- Local Wazuh `.deb` or `.rpm` discovery.
- Package SHA-256 reporting.
- Wazuh configuration backup.
- Core authentication/system/journal/audit/package/web-server log collection.
- FIM, SCA and Syscollector enablement.
- auditd rule deployment when auditd is already installed.
- Wazuh systemd restart-on-failure configuration.
- Agent enrollment unless skipped.
- TCP 1514/1515 validation.
- `WAZUH_READINESS_TEST` syslog marker generation.

Reports are written to:

```text
/var/log/soc-offline-deploy/
```

---

## 7. SOC Telemetry Baseline

### Windows minimum

Collect and validate:

- Security
- System
- Application
- Microsoft-Windows-PowerShell/Operational
- Microsoft-Windows-Sysmon/Operational
- Microsoft-Windows-Windows Defender/Operational
- Task Scheduler
- WMI Activity
- WinRM
- RDP session/connection channels
- Wazuh FIM
- Wazuh SCA
- Wazuh Syscollector

High-value Sysmon events should include at least:

- Event 1: Process creation
- Event 3: Network connection
- Event 6: Driver loaded
- Event 7: Image loaded; high-volume, tune carefully
- Event 8: CreateRemoteThread
- Event 10: ProcessAccess, especially LSASS-sensitive access
- Event 11: FileCreate
- Events 12/13/14: Registry changes
- Events 19/20/21: WMI persistence
- Event 22: DNS query
- Event 23/26: File deletion

### Linux minimum

Collect and validate:

- Authentication logs
- sudo/su activity
- SSH activity
- auditd events
- systemd/journald
- package installation/removal logs
- user/group changes
- cron/systemd persistence locations
- `/etc/ssh` changes
- critical identity files such as `/etc/passwd`, `/etc/shadow`, `/etc/group`
- web/database/application logs where applicable

---

## 8. Validation After Deployment

### Endpoint validation

Confirm:

- Wazuh service is running.
- Sysmon service is running on Windows.
- No repeated configuration errors appear in Wazuh `ossec.log`.
- Manager TCP 1514 is reachable.
- TCP 1515 is reachable when enrollment is required.
- Endpoint time is synchronized.

### Wazuh Manager/Dashboard validation

Verify:

- Agent status = Active.
- Agent IP/name/group are correct.
- Security/authentication events are arriving.
- Sysmon events are arriving on Windows.
- Syscollector inventory is populated.
- SCA results appear.
- FIM baseline completes.
- `WAZUH_READINESS_TEST` is searchable.
- Windows Application Event ID `9001` from source `SOCOfflineDeploy` is searchable.

Do not declare rollout successful only because the service is running locally. Confirm end-to-end event ingestion in the SIEM.

---

## 9. Production Rollout Controls

Recommended rollout sequence:

1. Lab endpoint.
2. One non-critical Windows workstation.
3. One Windows server.
4. One Linux server per supported distribution/version.
5. Domain Controller pilot if DC monitoring is in scope.
6. 24-48 hour telemetry/noise review.
7. Tune Sysmon/FIM/auditd filters.
8. Small production batch.
9. Full rollout after SOC validation.

Keep rollback copies of the previous Wazuh configuration. Use Wazuh groups/central configuration to keep endpoint-specific scripts small and maintainable.

---

## 10. Security Considerations

- Do not enable active response broadly without testing containment impact.
- Do not collect every high-volume log merely because it is available.
- Sysmon Event ID 7 can be extremely noisy; pilot it before enterprise-wide deployment.
- Event ID 10 should be tuned around sensitive targets such as LSASS rather than collecting all process-access events.
- Avoid globally monitoring volatile directories with realtime FIM.
- Store no enrollment passwords in Git, scripts, command history, or package directories.
- Restrict write access to the offline deployment bundle.
- Maintain package hashes and an internal release/change record.
- Pin and test Wazuh Agent/Sysmon versions before changing production packages.
- Review configuration after OS upgrades because event channels and package dependencies may change.

---

## 11. Recommended Next Enhancements

For mature SOC deployment, consider adding separate profiles/configurations for:

- Windows workstation
- Windows member server
- Active Directory Domain Controller
- Linux server
- Web server
- Database server
- Critical application server

Also consider centrally managed Wazuh `agent.conf` profiles so telemetry policy can be changed from the Wazuh Manager without rebuilding the offline installer bundle.
