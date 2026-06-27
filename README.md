# Wazuh Agent Auto Deploy + Security Recommendation Enforcer

It installs, configures, hardens, validates, and reports Wazuh Agent readiness for:

- Windows
- Linux
- macOS

---

## What This Combined Script Does

| Area | Automated Action |
|---|---|
| User input | Asks for Wazuh Manager IP/FQDN, Agent Name, Agent Group/Profile |
| Lab readiness | Creates lab-test/production-pilot acknowledgement marker |
| Manager connectivity | Checks TCP `1514`, `1515`, and optional `55000` |
| Agent install | Installs Wazuh Agent if missing |
| Agent config | Writes SOC-ready `ossec.conf` |
| Agent reliability | Enables auto-start and auto-recovery |
| Enrollment | Optionally runs `agent-auth` |
| Password policy | Checks/removes obvious plaintext enrollment password files |
| Windows security | Enables audit policy and PowerShell logging |
| Windows Sysmon | Checks and optionally installs Sysmon |
| Linux auditd | Installs/enables auditd and applies SOC audit rules |
| FIM tuning | Adds noise-control ignore entries |
| Validation | Generates test event marker `WAZUH_READINESS_TEST` |
| Reporting | Saves deployment/readiness report |

---

## Repository Structure

```text
wazuh-combined-auto-deploy/
├── README.md
├── LICENSE
├── .gitignore
├── deploy-combined-menu.sh
├── docs/
│   ├── USAGE.md
│   ├── SECURITY_RECOMMENDATIONS.md
│   └── VALIDATION.md
└── scripts/
    ├── windows/
    │   └── Invoke-Wazuh-Combined-Windows.ps1
    ├── linux/
    │   └── invoke-wazuh-combined-linux.sh
    └── macos/
        └── invoke-wazuh-combined-macos.sh
```

---

## Windows Usage

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\windows\Invoke-Wazuh-Combined-Windows.ps1
```

With parameters:

```powershell
.\scripts\windows\Invoke-Wazuh-Combined-Windows.ps1 `
  -Manager 10.10.10.50 `
  -AgentName HR-LAPTOP-01 `
  -AgentGroup "windows,soc,workstation" `
  -InstallSysmonIfMissing
```

Non-interactive example:

```powershell
.\scripts\windows\Invoke-Wazuh-Combined-Windows.ps1 `
  -Manager wazuh-manager.company.local `
  -AgentName HR-LAPTOP-01 `
  -AgentGroup "windows,soc,workstation" `
  -NonInteractive `
  -InstallSysmonIfMissing
```

---

## Linux Usage

```bash
chmod +x deploy-combined-menu.sh
./deploy-combined-menu.sh
```

Or directly:

```bash
sudo bash ./scripts/linux/invoke-wazuh-combined-linux.sh
```

With parameters:

```bash
sudo bash ./scripts/linux/invoke-wazuh-combined-linux.sh \
  --manager 10.10.10.50 \
  --agent-name linux-web-01 \
  --agent-group linux,soc,webserver
```

Non-interactive:

```bash
sudo bash ./scripts/linux/invoke-wazuh-combined-linux.sh \
  --manager wazuh-manager.company.local \
  --agent-name linux-web-01 \
  --agent-group linux,soc,webserver \
  --non-interactive
```

---

## macOS Usage

```bash
chmod +x deploy-combined-menu.sh
./deploy-combined-menu.sh
```

Or directly:

```bash
sudo bash ./scripts/macos/invoke-wazuh-combined-macos.sh
```

With parameters:

```bash
sudo bash ./scripts/macos/invoke-wazuh-combined-macos.sh \
  --manager 10.10.10.50 \
  --agent-name macbook-finance-01 \
  --agent-group macos,soc
```

---

## Dashboard Validation

After running the script, search in Wazuh Dashboard for:

```text
WAZUH_READINESS_TEST
```

For Windows, also search:

```text
WazuhReadiness
event.id: 9001
```

---

## Reports

### Windows

```text
C:\ProgramData\WazuhCombinedDeploy\
```

### Linux

```text
/var/log/wazuh-combined-deploy/
```

### macOS

```text
/Library/Logs/WazuhCombinedDeploy/
```

---

## Important Note

This script makes the agent production-ready and self-recovering **when the endpoint and network are available**.

It cannot prevent disconnection when:

- Endpoint is powered off
- Endpoint is asleep
- Endpoint has no network
- Firewall blocks Wazuh ports
- Wazuh Manager is unavailable
- Agent key is invalid
- Agent name/ID is duplicated
