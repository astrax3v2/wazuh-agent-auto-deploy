# Deployment Guide

## 1. Clone Repository

```bash
git clone https://github.com/astrax3v2/wazuh-agent-auto-deploy
cd wazuh-agent-auto-deploy
```

## 2. Open Required Ports

Allow agent to manager communication:

```text
TCP 1514 - Wazuh agent communication
TCP 1515 - Wazuh agent enrollment
```

## 3. Run Deployment

### Windows

Open PowerShell as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\windows\Deploy-Wazuh-Windows.ps1
```

### Linux

```bash
sudo bash ./scripts/linux/deploy-wazuh-linux.sh
```

### macOS

```bash
sudo bash ./scripts/macos/deploy-wazuh-macos.sh
```

## 4. Validate in Wazuh Dashboard

Go to:

```text
Wazuh Dashboard > Agents
```

Confirm:

```text
Agent status: Active
Logs received
Syscollector visible
SCA scan visible
FIM baseline completed
```
