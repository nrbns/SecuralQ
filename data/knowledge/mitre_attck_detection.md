# MITRE ATT&CK — Detection & Response (Blue Team)

## Tactic overview
| Tactic | Goal | Key log sources |
|--------|------|-----------------|
| Initial Access | Get in | Email gateway, proxy, VPN, WAF |
| Execution | Run code | Sysmon 1, EDR, PowerShell 4104 |
| Persistence | Survive reboot | Registry, scheduled tasks, services |
| Privilege Escalation | Elevate | Sysmon 10, 4672, sudo logs |
| Defense Evasion | Hide | AMSI bypass attempts, log clearing 1102 |
| Credential Access | Steal creds | 4624/4625, LSASS access Sysmon 10 |
| Discovery | Map environment | LDAP, net commands, port scans |
| Lateral Movement | Spread | 4624 type 3, SMB 5145, RDP 4778 |
| Collection | Gather data | Archive tools, clipboard, staging dirs |
| C2 | Command channel | DNS anomalies, rare JA3, beaconing |
| Exfiltration | Steal data | Large uploads, cloud API, DNS tunneling |
| Impact | Disrupt/encrypt | VSS deletion, mass file rename |

## Detection engineering workflow
1. Pick technique (e.g. T1003.001 LSASS memory)
2. Identify data sources (Sysmon, Windows Security, EDR)
3. Write detection rule (Sigma → SIEM)
4. Test with atomic red team **in lab**
5. Tune false positives
6. Document runbook

## Sigma example — suspicious PowerShell
```yaml
title: Encoded PowerShell Command
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
```

## Splunk example — failed then success login
```spl
index=wineventlog EventCode=4625
| stats count by src_ip, TargetUserName
| where count > 10
| join TargetUserName [
    search index=wineventlog EventCode=4624 Logon_Type=10
]
```

## Elastic EQL — LSASS access
```
process where event.type == "start" and
  process.name : "lsass.exe" and
  event.action == "access"
```

## Response playbook (generic)
1. **Triage** — severity, scope, affected assets
2. **Contain** — isolate host, disable account, block IOC at firewall/proxy
3. **Collect** — memory dump, disk image, logs (chain of custody)
4. **Eradicate** — remove malware, patch vuln, reset creds
5. **Recover** — restore from clean backup, monitor
6. **Post-incident** — timeline, root cause, detection gaps

## Hardening priorities
- MFA on all remote access
- EDR on endpoints + servers
- Network segmentation
- Patch management SLA
- Disable LLMNR/NBT-NS where possible
- LAPS for local admin passwords
- Centralized logging with retention
