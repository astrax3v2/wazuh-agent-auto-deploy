# Offline Package Staging

This directory is intentionally used for packages copied into an isolated environment.
Do not commit proprietary/internal packages unless your repository access policy allows it.

Expected structure:

```text
packages/
├── windows/
│   ├── wazuh-agent-<version>.msi
│   └── sysmon/
│       ├── Sysmon64.exe
│       └── sysmonconfig.xml
└── linux/
    ├── debian/
    │   └── wazuh-agent_<version>_amd64.deb
    └── rhel/
        └── wazuh-agent-<version>.x86_64.rpm
```

Optional prerequisite packages can also be staged under:

```text
packages/linux/debian/prereqs/
packages/linux/rhel/prereqs/
```

## Package preparation rules

1. Download packages from the official vendor repository from an internet-connected staging workstation.
2. Verify vendor signature/hash before transferring them into the isolated environment.
3. Record SHA-256 hashes in `packages/SHA256SUMS.txt`.
4. Transfer packages using your approved removable media, jump host, SFTP, or internal artifact repository.
5. Recalculate SHA-256 hashes after transfer and compare before installation.
6. Never place enrollment passwords, API credentials, private keys, or other secrets in this repository.

Example Windows hash command:

```powershell
Get-FileHash .\packages\windows\wazuh-agent-4.x.x-x.msi -Algorithm SHA256
```

Example Linux hash command:

```bash
sha256sum packages/linux/debian/wazuh-agent_4.x.x-1_amd64.deb
```
