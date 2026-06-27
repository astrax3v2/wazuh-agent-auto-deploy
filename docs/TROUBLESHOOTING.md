# Troubleshooting

## Agent Disconnected

Check endpoint service:

### Windows

```powershell
Get-Service WazuhSvc
Restart-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 80
```

### Linux

```bash
sudo systemctl status wazuh-agent
sudo systemctl restart wazuh-agent
sudo tail -n 80 /var/ossec/logs/ossec.log
```

### macOS

```bash
sudo /Library/Ossec/bin/wazuh-control status
sudo /Library/Ossec/bin/wazuh-control restart
sudo tail -n 80 /Library/Ossec/logs/ossec.log
```

## Network Test

```bash
nc -vz WAZUH_MANAGER 1514
nc -vz WAZUH_MANAGER 1515
```

Windows:

```powershell
Test-NetConnection WAZUH_MANAGER -Port 1514
Test-NetConnection WAZUH_MANAGER -Port 1515
```

## Common Causes

| Cause | Fix |
|---|---|
| Service stopped | Enable auto-start and recovery |
| Firewall blocked | Allow TCP 1514/1515 |
| Wrong manager IP/FQDN | Correct ossec.conf |
| Invalid key | Re-enroll agent |
| Duplicate agent name | Register unique name |
| Time drift | Enable NTP |
| Endpoint asleep/offline | Disable sleep for servers |
