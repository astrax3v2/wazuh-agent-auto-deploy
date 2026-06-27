# Integrated Security Recommendations

The combined script includes these production-readiness controls:

## 1. Lab Test Acknowledgement

Creates a marker only after confirmation that deployment was lab-tested or approved for production pilot.

## 2. Wazuh Manager Port Check

Checks:

- TCP 1514
- TCP 1515
- TCP 55000 unless skipped

## 3. Enrollment Password Handling

Searches common temporary/user locations for obvious plaintext password files and offers removal.

## 4. FIM Noise Review

Adds noise-control ignore paths and reminds SOC team to review FIM alerts after 24-48 hours.

## 5. Sysmon on Windows

Checks whether Sysmon exists. Can optionally install it.

## 6. auditd on Linux

Installs and enables auditd, then applies SOC rules for:

- identity files
- sudoers
- SSH config
- cron persistence
- systemd persistence
- log tampering
- privileged command execution
- kernel module load/unload

## 7. Dashboard Validation

Generates:

```text
WAZUH_READINESS_TEST
```

Search this marker in Wazuh Dashboard to confirm ingestion.
