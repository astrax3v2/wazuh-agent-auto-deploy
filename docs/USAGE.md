# Usage Guide

## Windows

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\windows\Invoke-Wazuh-Combined-Windows.ps1
```

Optional parameters:

```powershell
.\scripts\windows\Invoke-Wazuh-Combined-Windows.ps1 `
  -Manager 10.10.10.50 `
  -AgentName HR-LAPTOP-01 `
  -AgentGroup "windows,soc,workstation" `
  -InstallSysmonIfMissing
```

## Linux

```bash
sudo bash ./scripts/linux/invoke-wazuh-combined-linux.sh
```

Optional parameters:

```bash
sudo bash ./scripts/linux/invoke-wazuh-combined-linux.sh \
  --manager 10.10.10.50 \
  --agent-name linux-web-01 \
  --agent-group linux,soc,webserver
```

## macOS

```bash
sudo bash ./scripts/macos/invoke-wazuh-combined-macos.sh
```

Optional parameters:

```bash
sudo bash ./scripts/macos/invoke-wazuh-combined-macos.sh \
  --manager 10.10.10.50 \
  --agent-name macbook-01 \
  --agent-group macos,soc
```
