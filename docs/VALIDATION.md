# Validation

## Windows

```powershell
Get-Service WazuhSvc
Test-NetConnection WAZUH_MANAGER -Port 1514
Test-NetConnection WAZUH_MANAGER -Port 1515
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

Search Wazuh Dashboard for:

```text
WAZUH_READINESS_TEST
WazuhReadiness
event.id: 9001
```

## Linux

```bash
sudo systemctl status wazuh-agent
nc -vz WAZUH_MANAGER 1514
nc -vz WAZUH_MANAGER 1515
sudo tail -n 50 /var/ossec/logs/ossec.log
```

Search Wazuh Dashboard for:

```text
WAZUH_READINESS_TEST
```

## macOS

```bash
sudo /Library/Ossec/bin/wazuh-control status
nc -vz WAZUH_MANAGER 1514
nc -vz WAZUH_MANAGER 1515
sudo tail -n 50 /Library/Ossec/logs/ossec.log
```

Search Wazuh Dashboard for:

```text
WAZUH_READINESS_TEST
```
