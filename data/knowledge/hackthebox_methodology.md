# HackTheBox Methodology (Authorized VPN Lab Only)

## Connection
1. Download VPN pack from HTB account settings
2. Connect: `sudo openvpn lab.ovpn` (Linux) or OpenVPN GUI (Windows)
3. Verify: ping `10.10.10.1` or check HTB connection page

## Standard workflow
```bash
# 1. Initial scan
nmap -sC -sV -oA nmap/initial <target_ip>

# 2. Full port scan (if needed)
nmap -p- --min-rate 5000 -oA nmap/allports <target_ip>

# 3. UDP top ports (optional)
nmap -sU --top-ports 50 <target_ip>
```

## Service enumeration cheatsheet
| Port | Tools |
|------|-------|
| 21 FTP | `ftp`, anonymous login, `nmap --script ftp-*` |
| 22 SSH | `ssh -v`, check for weak creds in CTF context |
| 80/443 Web | `gobuster dir`, `ffuf`, Burp, `nikto` |
| 139/445 SMB | `enum4linux -a`, `smbclient -L`, `crackmapexec smb` |
| 3306 MySQL | `mysql -h <ip> -u root -p`, nmap mysql scripts |
| 5985 WinRM | `evil-winrm -i <ip> -u user -p pass` (lab creds) |

## Web enumeration
```bash
gobuster dir -u http://<ip> -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50
ffuf -u http://<ip>/FUZZ -w common.txt -fc 404
whatweb http://<ip>
```

## Privilege escalation (Linux lab boxes)
```bash
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab
linpeas.sh   # run only in authorized lab VM
```

## Privilege escalation (Windows lab boxes)
```powershell
whoami /priv
systeminfo
winPEASx64.exe   # lab VM only
```

## Rules
- Stay on HTB VPN network only
- No attacking other players or HTB infrastructure
- Document findings as you go for writeups
