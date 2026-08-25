# Threat Hunting Playbook

## Hypothesis-driven hunting
1. **Hypothesis** — e.g. "Attackers may use living-off-the-land binaries"
2. **Data** — Sysmon, EDR, proxy, DNS logs
3. **Query** — SIEM search for unusual parent-child chains
4. **Investigate** — pivot on host, user, hash
5. **Detect** — convert finding to permanent rule

## LOLBAS patterns to hunt
| Binary | Suspicious use |
|--------|----------------|
| `certutil.exe` | `-urlcache -split -f` download |
| `mshta.exe` | remote script execution |
| `regsvr32.exe` | `/s /n /u /i:http` squiblydoo |
| `rundll32.exe` | no DLL in command line |
| `wmic.exe` | process creation remotely |

## Sysmon hunt queries (conceptual)
- `Image` ends with `powershell.exe` AND parent is `winword.exe` or `excel.exe`
- `GrantedAccess` to lsass from non-system process
- Service creation with binary in `Users\` or `Temp\`

## DNS hunting
- High entropy subdomains (DGA)
- NXDOMAIN spikes from single host
- Rare TLDs (.xyz, .top) from servers

## Baseline first
Establish normal for:
- Admin tool usage per role
- Outbound destinations per server tier
- Login hours per user group

Deviations become hunt leads.

## Hunt report template
- Hypothesis
- Data sources searched
- Queries used
- Findings (true positive / benign / inconclusive)
- Recommended detection rule
- ATT&CK mapping
