# Active Directory Security (Blue Team)

## High-value targets
- Domain Controllers
- Tier 0 admin accounts
- AD CS (Certificate Services)
- Azure AD Connect servers

## Common attack paths
| Path | Technique | Detection |
|------|-----------|-----------|
| Kerberoasting | T1558.003 | Event 4769, RC4 encryption type |
| AS-REP roasting | T1558.004 | Event 4768, preauth disabled |
| DCSync | T1003.006 | Event 4662 replication rights |
| Golden Ticket | T1558.001 | anomalous TGT lifetime |
| Pass-the-Hash | T1550.002 | NTLM type 3 from unusual source |

## Hardening checklist
- [ ] Tiered admin model (Tier 0/1/2)
- [ ] LAPS on all workstations
- [ ] Disable NTLM where possible
- [ ] Protected Users group for admins
- [ ] Audit policy: 4662, 4769, 4768, 4624
- [ ] gMSA for service accounts
- [ ] BloodHound audit — find paths to DA

## BloodHound (defensive use)
Run in lab or with read-only collector on authorized domain:
```bash
bloodhound-python -u auditor -p 'pass' -d corp.local -ns 10.0.0.1 -c All
```
Review: shortest paths to Domain Admins, unconstrained delegation, AS-REP roastable users.

## Kerberoasting detection (Splunk)
```spl
index=wineventlog EventCode=4769
Service_Name!="krbtgt" Service_Name!="*$"
| stats count by Service_Name, Account_Name
| where count > 5
```

## Response
1. Reset service account passwords (long random)
2. Remove unnecessary SPNs
3. Enable AES-only for Kerberos where supported
4. Investigate source of roast requests
