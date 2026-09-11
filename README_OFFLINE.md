# Offline Wazuh + Sysmon SOC Deployment

This branch adds an offline/air-gapped deployment path to the existing Wazuh auto-deployment project.

## Goal

Deploy SOC endpoint telemetry without requiring the target endpoint to access the internet.

## Components

- Windows
  - Wazuh Agent from local MSI
  - Sysmon from local executable/config
  - Windows Advanced Audit Policy
  - PowerShell Script Block/Module Logging
  - Wazuh FIM, SCA and Syscollector
  - Service startup/recovery
  - End-to-end readiness marker
- Linux
  - Wazuh Agent from local DEB/RPM
  - auditd integration when available
  - authentication/system/package/application log coverage
  - Wazuh FIM, SCA and Syscollector
  - systemd service recovery
  - end-to-end readiness marker

## Quick Start

1. Read `docs/OFFLINE_DEPLOYMENT.md`.
2. Populate packages as documented in `packages/README.md`.
3. For Sysmon, copy `configs/sysmonconfig-soc.xml` to `packages/windows/sysmon/sysmonconfig.xml` unless an internally approved configuration is used.
4. Verify SHA-256 hashes/signatures.
5. Run a lab deployment before production rollout.

### Windows

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\Invoke-SOC-Offline-Windows.ps1 `
  -Manager 10.10.10.50 `
  -AgentName SERVER01 `
  -AgentGroup "windows,soc,server"
```

### Linux

```bash
sudo bash scripts/invoke-soc-offline-linux.sh \
  --manager 10.10.10.50 \
  --agent-name linux01 \
  --agent-group linux,soc,server
```

## Important

The repository intentionally does not contain Wazuh or Sysmon binaries. Stage approved packages yourself and keep version/hash records under change control.
